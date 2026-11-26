"""TLS posture ledger: per-round endpoint records, downgrade regressions, waivers and history."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from datetime import datetime, timezone


class LedgerError(ValueError):
    """Raised when a ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


PROTOCOLS = ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")

STATE_OPEN = "open"
STATE_WAIVED = "waived"
STATE_RESOLVED = "resolved"

KIND_DOWNGRADE = "protocol_downgrade"
KIND_SUITE_REMOVED = "suite_removed"
KIND_ISSUER_CHANGED = "cert_issuer_changed"
KIND_CERT_EXPIRING = "cert_expiring"

_FORMAT = "tls-posture-ledger-v1"
_DAY = 86400
_COUNTER_KEYS = ("rounds", "endpoints", "regressions", "waived", "reopened")
_REGRESSION_STATES = (STATE_OPEN, STATE_WAIVED, STATE_RESOLVED)


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _seconds(value) -> int:
    """Turn an epoch value into integer seconds without using the host timezone."""
    if _is_int(value):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, datetime):
        moment = value
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return int(moment.timestamp())
    raise TypeError("expected integer seconds")


def _copy_detail(detail):
    if isinstance(detail, dict):
        return dict(detail)
    if isinstance(detail, tuple):
        return tuple(detail)
    if isinstance(detail, list):
        return list(detail)
    return detail


def _copy_regression(row: dict) -> dict:
    copied = dict(row)
    if "detail" in copied:
        copied["detail"] = _copy_detail(copied["detail"])
    return copied


class TlsPostureLedger:
    """Keep the newest scan rounds and turn posture changes into tracked regressions."""

    def __init__(self, *, history_rounds: int = 3,
                 cert_warning_days: int = 30) -> None:
        if not _is_int(history_rounds) or history_rounds < 1:
            raise ValueError("history_rounds must be a positive integer")
        if not _is_int(cert_warning_days) or cert_warning_days < 0:
            raise ValueError("cert_warning_days must be a non-negative integer")
        self.history_rounds = history_rounds
        self.cert_warning_days = cert_warning_days
        self._lock = threading.RLock()
        self._rounds = {}
        self._endpoints = {}
        self._regressions = {}
        self._next_regression = 1
        self._counters = {key: 0 for key in _COUNTER_KEYS}

    @staticmethod
    def _clean_scan(endpoints) -> dict:
        if isinstance(endpoints, (str, bytes, Mapping)):
            raise LedgerError("TLS_INVALID_SCAN", "endpoints must be a sequence")
        try:
            items = list(endpoints)
        except TypeError as exc:
            raise LedgerError("TLS_INVALID_SCAN", "endpoints must be a sequence") from exc
        if not items:
            raise LedgerError("TLS_INVALID_SCAN", "endpoints must not be empty")

        records = {}
        protocol_set = set(PROTOCOLS)
        for item in items:
            if not isinstance(item, Mapping):
                raise LedgerError("TLS_INVALID_SCAN", "endpoint entry must be a mapping")
            endpoint = item.get("endpoint")
            if not isinstance(endpoint, str) or not endpoint.strip():
                raise LedgerError("TLS_INVALID_SCAN", "endpoint must not be empty")
            if endpoint in records:
                raise LedgerError("TLS_INVALID_SCAN",
                                  f"duplicate endpoint: {endpoint}")

            protocols = item.get("protocols")
            if isinstance(protocols, (str, bytes, Mapping)):
                raise LedgerError("TLS_INVALID_SCAN",
                                  f"bad protocols for {endpoint}")
            try:
                protocol_items = list(protocols)
            except TypeError as exc:
                raise LedgerError("TLS_INVALID_SCAN",
                                  f"bad protocols for {endpoint}") from exc
            if not protocol_items:
                raise LedgerError("TLS_INVALID_SCAN",
                                  f"empty protocols for {endpoint}")
            normalized_protocols = set()
            for protocol in protocol_items:
                if not isinstance(protocol, str) or protocol not in protocol_set:
                    raise LedgerError("TLS_INVALID_SCAN",
                                      f"unsupported protocol: {protocol!r}")
                normalized_protocols.add(protocol)

            suites = item.get("suites")
            if isinstance(suites, (str, bytes, Mapping)):
                raise LedgerError("TLS_INVALID_SCAN",
                                  f"bad suites for {endpoint}")
            try:
                suite_items = list(suites)
            except TypeError as exc:
                raise LedgerError("TLS_INVALID_SCAN",
                                  f"bad suites for {endpoint}") from exc
            if not suite_items:
                raise LedgerError("TLS_INVALID_SCAN",
                                  f"empty suites for {endpoint}")
            normalized_suites = set()
            for suite in suite_items:
                if not isinstance(suite, str) or not suite.strip():
                    raise LedgerError("TLS_INVALID_SCAN",
                                      f"bad suite for {endpoint}")
                normalized_suites.add(suite)

            issuer = item.get("cert_issuer")
            if not isinstance(issuer, str) or not issuer.strip():
                raise LedgerError("TLS_INVALID_SCAN",
                                  f"empty cert_issuer for {endpoint}")

            try:
                not_after = _seconds(item.get("cert_not_after"))
            except (TypeError, ValueError, OverflowError) as exc:
                raise LedgerError("TLS_INVALID_SCAN",
                                  f"bad cert_not_after for {endpoint}") from exc
            if not_after <= 0:
                raise LedgerError("TLS_INVALID_SCAN",
                                  f"bad cert_not_after for {endpoint}")

            records[endpoint] = {
                "protocols": tuple(sorted(normalized_protocols)),
                "suites": tuple(sorted(normalized_suites)),
                "cert_issuer": issuer,
                "cert_not_after": not_after,
            }
        return records

    def _changes(self, previous, current, has_previous: bool) -> list:
        changes = []
        for endpoint, record in current.items():
            before = previous.get(endpoint) if has_previous else None
            if has_previous and before is None:
                if record["protocols"]:
                    changes.append({
                        "endpoint": endpoint,
                        "kind": "protocol_added",
                        "detail": tuple(record["protocols"]),
                    })
                if record["suites"]:
                    changes.append({
                        "endpoint": endpoint,
                        "kind": "suite_added",
                        "detail": tuple(record["suites"]),
                    })
            elif before is not None:
                old_protocols = set(before["protocols"])
                new_protocols = set(record["protocols"])
                removed_protocols = tuple(sorted(old_protocols - new_protocols))
                added_protocols = tuple(sorted(new_protocols - old_protocols))
                if removed_protocols:
                    changes.append({
                        "endpoint": endpoint,
                        "kind": "protocol_removed",
                        "detail": removed_protocols,
                    })
                if added_protocols:
                    changes.append({
                        "endpoint": endpoint,
                        "kind": "protocol_added",
                        "detail": added_protocols,
                    })

                old_suites = set(before["suites"])
                new_suites = set(record["suites"])
                removed_suites = tuple(sorted(old_suites - new_suites))
                added_suites = tuple(sorted(new_suites - old_suites))
                if removed_suites:
                    changes.append({
                        "endpoint": endpoint,
                        "kind": KIND_SUITE_REMOVED,
                        "detail": removed_suites,
                    })
                if added_suites:
                    changes.append({
                        "endpoint": endpoint,
                        "kind": "suite_added",
                        "detail": added_suites,
                    })

                if before["cert_issuer"] != record["cert_issuer"]:
                    changes.append({
                        "endpoint": endpoint,
                        "kind": KIND_ISSUER_CHANGED,
                        "detail": {"from": before["cert_issuer"],
                                   "to": record["cert_issuer"]},
                    })
        changes.sort(key=lambda change: (change["endpoint"], change["kind"]))
        return changes

    def _new_regression_candidates(self, changes: list, records: dict,
                                   now: int) -> list:
        cross_priority = {
            "protocol_removed": 0,
            KIND_SUITE_REMOVED: 1,
            KIND_ISSUER_CHANGED: 2,
        }
        cross = {}
        for change in changes:
            endpoint = change["endpoint"]
            kind = change["kind"]
            detail = change["detail"]
            if kind in cross_priority:
                regression_kind = (KIND_DOWNGRADE
                                   if kind == "protocol_removed" else kind)
                priority = cross_priority[kind]
                if (endpoint not in cross
                        or priority < cross[endpoint][0]):
                    cross[endpoint] = (priority, endpoint, regression_kind,
                                       detail)
        candidates = [(endpoint, kind, detail)
                      for _, endpoint, kind, detail in cross.values()]
        for endpoint, record in records.items():
            days_left = (record["cert_not_after"] - now) // _DAY
            if days_left < self.cert_warning_days:
                candidates.append((
                    endpoint,
                    KIND_CERT_EXPIRING,
                    {"not_after": record["cert_not_after"],
                     "days_left": days_left},
                ))
        candidates.sort(key=lambda item: (item[0], item[1]))
        return candidates

    @staticmethod
    def _regression_sort_key(row: dict) -> int:
        return int(row["regression_id"].split("-")[1])

    def _has_matching_regression(self, endpoint: str, kind: str) -> bool:
        for row in self._regressions.values():
            if row["endpoint"] != endpoint or row["kind"] != kind:
                continue
            return True
        return False

    def _open_regressions(self, candidates: list, round_no: int) -> None:
        for endpoint, kind, detail in candidates:
            if self._has_matching_regression(endpoint, kind):
                continue
            regression_id = f"REG-{self._next_regression:04d}"
            self._next_regression += 1
            self._regressions[regression_id] = {
                "regression_id": regression_id,
                "endpoint": endpoint,
                "kind": kind,
                "state": STATE_OPEN,
                "opened_round": round_no,
                "detail": _copy_detail(detail),
            }
            self._counters["regressions"] += 1

    def _prune(self) -> int:
        pruned = 0
        while len(self._rounds) > self.history_rounds:
            oldest = next(iter(self._rounds))
            del self._rounds[oldest]
            pruned += 1
        return pruned

    def _latest_round(self):
        if not self._rounds:
            return None
        return max(self._rounds)

    def record_scan(self, round_no: int, *, endpoints, now: int) -> dict:
        with self._lock:
            if not _is_int(round_no) or round_no <= 0:
                raise LedgerError("TLS_INVALID_SCAN",
                                  "round must be a positive integer")
            try:
                scan_now = _seconds(now)
            except (TypeError, ValueError, OverflowError) as exc:
                raise LedgerError("TLS_INVALID_SCAN",
                                  "now must be an integer timestamp") from exc
            records = self._clean_scan(endpoints)

            latest = self._latest_round()
            if latest is not None and round_no <= latest:
                raise LedgerError("TLS_ROUND_ORDER",
                                  {"round": round_no, "last": latest})

            previous = self._rounds[latest]["endpoints"] if latest else {}
            unreachable = 0
            if latest is not None:
                unreachable = sum(1 for endpoint in previous
                                  if endpoint not in records)
            changes = self._changes(previous, records, latest is not None)
            candidates = self._new_regression_candidates(changes, records,
                                                         scan_now)

            newly_seen = sum(1 for endpoint in records
                             if endpoint not in self._endpoints)
            self._rounds[round_no] = {
                "now": scan_now,
                "endpoints": records,
            }
            for endpoint, record in records.items():
                self._endpoints[endpoint] = dict(record,
                                                 last_round=round_no)
            self._counters["rounds"] += 1
            self._counters["endpoints"] += newly_seen
            self._open_regressions(candidates, round_no)
            pruned = self._prune()
            return {
                "round": round_no,
                "endpoints": len(records),
                "unreachable": unreachable,
                "pruned": pruned,
            }

    def diff_round(self, round_no: int) -> dict:
        with self._lock:
            if not _is_int(round_no) or round_no not in self._rounds:
                raise LedgerError("TLS_ROUND_UNKNOWN", round_no)
            earlier = [number for number in self._rounds
                       if number < round_no]
            previous_round = max(earlier) if earlier else None
            if previous_round is None:
                previous = {}
                has_previous = False
            else:
                previous = self._rounds[previous_round]["endpoints"]
                has_previous = True
            current = self._rounds[round_no]["endpoints"]
            changes = self._changes(previous, current, has_previous)
            return {
                "round": round_no,
                "previous": previous_round,
                "changes": tuple(changes),
            }

    def regress(self, round_no: int) -> tuple:
        with self._lock:
            if not _is_int(round_no) or round_no not in self._rounds:
                raise LedgerError("TLS_ROUND_UNKNOWN", round_no)
            rows = [row for row in self._regressions.values()
                    if row["opened_round"] == round_no]
            rows.sort(key=self._regression_sort_key)
            return tuple(_copy_regression(row) for row in rows)

    def waive(self, regression_id: str, *, until: int, reason: str,
              now: int) -> dict:
        with self._lock:
            row = (self._regressions.get(regression_id)
                   if isinstance(regression_id, str) else None)
            if row is None:
                raise LedgerError("TLS_REGRESSION_UNKNOWN", regression_id)
            try:
                until_at = _seconds(until)
                waived_at = _seconds(now)
            except (TypeError, ValueError, OverflowError) as exc:
                raise LedgerError("TLS_BAD_WAIVER",
                                  "until and now must be timestamps") from exc
            if not isinstance(reason, str) or not reason.strip():
                raise LedgerError("TLS_BAD_WAIVER", "reason must not be empty")
            if until_at <= waived_at:
                raise LedgerError("TLS_BAD_WAIVER",
                                  "until must be after now")
            if row["state"] != STATE_OPEN:
                raise LedgerError("TLS_BAD_WAIVER",
                                  {"state": row["state"]})
            row["state"] = STATE_WAIVED
            row["waived_until"] = until_at
            row["waive_reason"] = reason
            self._counters["waived"] += 1
            return _copy_regression(row)

    def resolve(self, regression_id: str, *, now: int) -> dict:
        with self._lock:
            row = (self._regressions.get(regression_id)
                   if isinstance(regression_id, str) else None)
            if row is None:
                raise LedgerError("TLS_REGRESSION_UNKNOWN", regression_id)
            if row["state"] == STATE_RESOLVED:
                raise LedgerError("TLS_REGRESSION_STATE",
                                  {"regression_id": regression_id,
                                   "state": row["state"]})
            try:
                resolved_at = _seconds(now)
            except (TypeError, ValueError, OverflowError) as exc:
                raise LedgerError("TLS_REGRESSION_STATE",
                                  "now must be a timestamp") from exc
            row["state"] = STATE_RESOLVED
            row["resolved_at"] = resolved_at
            return _copy_regression(row)

    def regressions(self, *, state: str | None = None) -> tuple:
        with self._lock:
            if state is not None and state not in _REGRESSION_STATES:
                raise LedgerError("TLS_REGRESSION_STATE",
                                  {"state": state})
            rows = [
                row for row in self._regressions.values()
                if state is None or row["state"] == state
            ]
            rows.sort(key=self._regression_sort_key)
            return tuple(_copy_regression(row) for row in rows)

    def history(self, *, endpoint: str | None = None) -> tuple:
        with self._lock:
            if endpoint is None:
                return tuple(self._rounds)
            if not isinstance(endpoint, str):
                return ()
            return tuple(
                round_no for round_no, payload in self._rounds.items()
                if endpoint in payload["endpoints"]
            )

    def endpoint_state(self, endpoint: str) -> dict:
        with self._lock:
            record = (self._endpoints.get(endpoint)
                      if isinstance(endpoint, str) else None)
            if record is None:
                raise LedgerError("TLS_ENDPOINT_UNKNOWN", endpoint)
            latest = self._latest_round()
            return {
                "endpoint": endpoint,
                "protocols": tuple(record["protocols"]),
                "suites": tuple(record["suites"]),
                "cert_issuer": record["cert_issuer"],
                "cert_not_after": record["cert_not_after"],
                "last_round": record["last_round"],
                "unreachable": latest is None
                or record["last_round"] != latest,
            }

    def summary(self, round_no: int) -> dict:
        with self._lock:
            if not _is_int(round_no) or round_no not in self._rounds:
                raise LedgerError("TLS_ROUND_UNKNOWN", round_no)
            records = self._rounds[round_no]["endpoints"]
            protocols = {protocol: 0 for protocol in PROTOCOLS}
            for record in records.values():
                for protocol in record["protocols"]:
                    protocols[protocol] += 1
            return {
                "round": round_no,
                "endpoints": len(records),
                "protocols": protocols,
                "open_regressions": sum(
                    1 for row in self._regressions.values()
                    if row["state"] == STATE_OPEN),
                "waived_regressions": sum(
                    1 for row in self._regressions.values()
                    if row["state"] == STATE_WAIVED),
            }

    def sweep(self, *, now: int) -> dict:
        with self._lock:
            try:
                swept_at = _seconds(now)
            except (TypeError, ValueError, OverflowError) as exc:
                raise LedgerError("TLS_BAD_WAIVER",
                                  "now must be a timestamp") from exc
            reopened = 0
            for row in self._regressions.values():
                if (row["state"] == STATE_WAIVED
                        and row.get("waived_until", swept_at + 1) <= swept_at):
                    row["state"] = STATE_OPEN
                    reopened += 1
            self._counters["reopened"] += reopened
            pruned = self._prune()
            return {"reopened": reopened, "pruned_rounds": pruned}

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def snapshot(self) -> dict:
        with self._lock:
            history = []
            for round_no, payload in self._rounds.items():
                endpoints = []
                for endpoint, record in sorted(
                        payload["endpoints"].items()):
                    endpoints.append({
                        "endpoint": endpoint,
                        "protocols": list(record["protocols"]),
                        "suites": list(record["suites"]),
                        "cert_issuer": record["cert_issuer"],
                        "cert_not_after": record["cert_not_after"],
                    })
                history.append({
                    "round": round_no,
                    "now": payload["now"],
                    "endpoints": endpoints,
                })
            endpoint_rows = []
            for endpoint, record in sorted(self._endpoints.items()):
                endpoint_rows.append({
                    "endpoint": endpoint,
                    "protocols": list(record["protocols"]),
                    "suites": list(record["suites"]),
                    "cert_issuer": record["cert_issuer"],
                    "cert_not_after": record["cert_not_after"],
                    "last_round": record["last_round"],
                })
            return {
                "format": _FORMAT,
                "rounds": {
                    "history": history,
                    "endpoints": endpoint_rows,
                },
                "regressions": [
                    _copy_regression(row)
                    for row in self._regressions.values()
                ],
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._validated_snapshot(state)
            except LedgerError:
                raise
            except Exception as exc:
                raise LedgerError("TLS_SNAPSHOT_INVALID") from exc
            rounds, endpoint_rows, regressions, counters, next_regression = \
                restored
            self._rounds = rounds
            self._endpoints = endpoint_rows
            self._regressions = regressions
            self._next_regression = next_regression
            self._counters = counters

    def _validated_snapshot(self, state):
        if not isinstance(state, Mapping):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "snapshot must be a mapping")
        if set(state) != {"format", "rounds", "regressions", "counters"}:
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad snapshot keys")
        if state.get("format") != _FORMAT:
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad format")

        rounds_block = state.get("rounds")
        if not isinstance(rounds_block, Mapping):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad rounds")
        if set(rounds_block) != {"history", "endpoints"}:
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad rounds keys")
        history_block = rounds_block.get("history")
        endpoint_block = rounds_block.get("endpoints")
        if not isinstance(history_block, list):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad history")
        if not isinstance(endpoint_block, list):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad endpoints")

        rounds = {}
        last_round = 0
        for entry in history_block:
            if not isinstance(entry, Mapping):
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad round entry")
            if set(entry) != {"round", "now", "endpoints"}:
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad round keys")
            round_no = entry.get("round")
            if not _is_int(round_no) or round_no <= 0 or round_no <= last_round:
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad round number")
            now = entry.get("now")
            if not _is_int(now):
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad round now")
            endpoint_entries = entry.get("endpoints")
            if not isinstance(endpoint_entries, list):
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad round endpoints")
            records = self._restored_endpoints(endpoint_entries,
                                               require_last_round=False)
            rounds[round_no] = {"now": now, "endpoints": records}
            last_round = round_no

        endpoints = self._restored_endpoints(endpoint_block,
                                             require_last_round=True)

        regressions_block = state.get("regressions")
        if not isinstance(regressions_block, list):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad regressions")
        regressions = {}
        highest_regression = 0
        for row in regressions_block:
            cleaned = self._validated_regression(row)
            regression_id = cleaned["regression_id"]
            if regression_id in regressions:
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "duplicate regression id")
            regressions[regression_id] = cleaned
            highest_regression = max(highest_regression,
                                     int(regression_id.split("-")[1]))

        counters_block = state.get("counters")
        if not isinstance(counters_block, Mapping):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad counters")
        if set(counters_block) != set(_COUNTER_KEYS):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad counter keys")
        counters = {}
        for key in _COUNTER_KEYS:
            value = counters_block.get(key)
            if not _is_int(value) or value < 0:
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  f"bad counter: {key}")
            counters[key] = value

        return (rounds, endpoints, regressions, counters,
                highest_regression + 1)

    def _restored_endpoints(self, entries, *, require_last_round: bool) -> dict:
        records = {}
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad endpoint entry")
            expected = {"endpoint", "protocols", "suites", "cert_issuer",
                        "cert_not_after"}
            if require_last_round:
                expected.add("last_round")
            if set(entry) != expected:
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad endpoint keys")
            endpoint = entry.get("endpoint")
            if not isinstance(endpoint, str) or not endpoint.strip():
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad endpoint")
            if endpoint in records:
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "duplicate endpoint")

            protocols = entry.get("protocols")
            if not isinstance(protocols, list) or not protocols:
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad protocols")
            if any(not isinstance(protocol, str)
                   or protocol not in PROTOCOLS for protocol in protocols):
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad protocols")
            suites = entry.get("suites")
            if not isinstance(suites, list) or not suites:
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad suites")
            if any(not isinstance(suite, str) or not suite.strip()
                   for suite in suites):
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad suites")
            issuer = entry.get("cert_issuer")
            if not isinstance(issuer, str) or not issuer.strip():
                raise LedgerError("TLS_SNAPSHOT_INVALID", "bad cert_issuer")
            not_after = entry.get("cert_not_after")
            if not _is_int(not_after) or not_after <= 0:
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad cert_not_after")

            record = {
                "protocols": tuple(sorted(set(protocols))),
                "suites": tuple(sorted(set(suites))),
                "cert_issuer": issuer,
                "cert_not_after": not_after,
            }
            if require_last_round:
                last = entry.get("last_round")
                if not _is_int(last) or last <= 0:
                    raise LedgerError("TLS_SNAPSHOT_INVALID",
                                      "bad last_round")
                record["last_round"] = last
            records[endpoint] = record
        return records

    def _validated_regression(self, row) -> dict:
        if not isinstance(row, Mapping):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad regression entry")
        required = {"regression_id", "endpoint", "kind", "state",
                    "opened_round", "detail"}
        if not required.issubset(set(row)):
            raise LedgerError("TLS_SNAPSHOT_INVALID",
                              "bad regression fields")
        allowed = required | {"waived_until", "waive_reason", "resolved_at"}
        if set(row) - allowed:
            raise LedgerError("TLS_SNAPSHOT_INVALID",
                              "bad regression fields")

        regression_id = row.get("regression_id")
        if not isinstance(regression_id, str):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad regression id")
        parts = regression_id.split("-")
        if (len(parts) != 2 or parts[0] != "REG"
                or not parts[1].isdigit()
                or int(parts[1]) <= 0):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad regression id")
        endpoint = row.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad regression endpoint")
        kind = row.get("kind")
        if kind not in (KIND_DOWNGRADE, KIND_SUITE_REMOVED,
                        KIND_ISSUER_CHANGED, KIND_CERT_EXPIRING):
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad regression kind")
        state_value = row.get("state")
        if state_value not in _REGRESSION_STATES:
            raise LedgerError("TLS_SNAPSHOT_INVALID", "bad regression state")
        opened_round = row.get("opened_round")
        if not _is_int(opened_round) or opened_round <= 0:
            raise LedgerError("TLS_SNAPSHOT_INVALID",
                              "bad regression round")
        if "detail" not in row:
            raise LedgerError("TLS_SNAPSHOT_INVALID",
                              "missing regression detail")

        detail = row.get("detail")
        if kind in (KIND_DOWNGRADE, KIND_SUITE_REMOVED):
            if not isinstance(detail, (tuple, list)):
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad regression detail")
            if any(not isinstance(value, str) for value in detail):
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad regression detail")
            detail = tuple(detail)
        elif kind == KIND_ISSUER_CHANGED:
            if not isinstance(detail, Mapping):
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad regression detail")
            if set(detail) != {"from", "to"}:
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad regression detail")
            if not all(isinstance(value, str) for value in detail.values()):
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad regression detail")
            detail = {"from": detail["from"], "to": detail["to"]}
        elif kind == KIND_CERT_EXPIRING:
            if not isinstance(detail, Mapping):
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad regression detail")
            if set(detail) != {"not_after", "days_left"}:
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad regression detail")
            if (not _is_int(detail.get("not_after"))
                    or not _is_int(detail.get("days_left"))):
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad regression detail")
            detail = {"not_after": detail["not_after"],
                      "days_left": detail["days_left"]}

        cleaned = {
            "regression_id": regression_id,
            "endpoint": endpoint,
            "kind": kind,
            "state": state_value,
            "opened_round": opened_round,
            "detail": detail,
        }
        if state_value == STATE_WAIVED:
            waived_until = row.get("waived_until")
            waive_reason = row.get("waive_reason")
            if not _is_int(waived_until):
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad waived_until")
            if not isinstance(waive_reason, str) or not waive_reason.strip():
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad waive_reason")
        if state_value == STATE_RESOLVED:
            resolved_at = row.get("resolved_at")
            if not _is_int(resolved_at):
                raise LedgerError("TLS_SNAPSHOT_INVALID",
                                  "bad resolved_at")
        for key in ("waived_until", "waive_reason", "resolved_at"):
            if key in row:
                cleaned[key] = row[key]
        return cleaned
