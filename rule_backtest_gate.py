"""Replay gate that scores a candidate detection rule against a historical sample set."""

from __future__ import annotations

import copy
import threading
from collections.abc import Iterable


class BacktestError(ValueError):
    """Raised when a gate operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SAMPLE_LABELS = ("malicious", "benign")
BASELINE_STATES = ("hit", "miss", "absent")

RUN_RUNNING = "running"
RUN_PAUSED = "paused"
RUN_INTERRUPTED = "interrupted"
RUN_COMPLETED = "completed"

VERDICT_ACCEPT = "accept"
VERDICT_REJECT = "reject"

REASON_NEW_HITS = "NEW_HITS_OVER_LIMIT"
REASON_FP_DELTA = "FP_DELTA_OVER_LIMIT"

ERR_INVALID_RULE = "BACKTEST_INVALID_RULE"
ERR_INVALID_SAMPLES = "BACKTEST_INVALID_SAMPLES"
ERR_BASELINE_MISMATCH = "BACKTEST_BASELINE_MISMATCH"
ERR_UNKNOWN_RULE = "BACKTEST_UNKNOWN_RULE"
ERR_UNKNOWN_SAMPLES = "BACKTEST_UNKNOWN_SAMPLES"
ERR_UNKNOWN_RUN = "BACKTEST_UNKNOWN_RUN"
ERR_RUN_STATE = "BACKTEST_RUN_STATE"
ERR_RUN_NOT_READY = "BACKTEST_RUN_NOT_READY"
ERR_SNAPSHOT_INVALID = "BACKTEST_SNAPSHOT_INVALID"
ERR_INVALID_BATCH = "BACKTEST_INVALID_BATCH"
ERR_INVALID_CONFIG = "BACKTEST_INVALID_CONFIG"

_SNAPSHOT_FORMAT = "rule-backtest-gate-v1"
_SNAPSHOT_KEYS = {"format", "baselines", "candidates", "samplesets",
                  "runs", "counters"}
_BASE_KEYS = {"rule_id", "version"}
_CANDIDATE_KEYS = {"rule_id", "version", "selectors"}
_SAMPLESET_KEYS = {"sampleset_id", "version", "baseline_version", "total",
                   "samples"}
_SAMPLE_KEYS = {"sample_id", "label", "tags", "baseline_state"}
_RUN_KEYS = {
    "run_id", "status", "candidate_id", "baseline_id", "sampleset_id",
    "candidate_version", "baseline_version", "sampleset_version",
    "batch_size", "candidate_selectors", "samples", "total", "total_batches",
    "next_batch", "processed", "candidate_hits", "baseline_hits", "scored",
    "new_hits", "candidate_fp", "baseline_fp", "batches", "decision",
}
_COUNTER_KEYS = {"next_run", "accepted", "rejected"}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_positive(value: object) -> bool:
    return _is_int(value) and value > 0


def _identifier(value: object, code: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BacktestError(code, {"field": field})
    return value


def _normalize_selectors(selectors: object, code: str) -> tuple[str, ...]:
    if isinstance(selectors, (str, bytes)) or not isinstance(selectors, Iterable):
        raise BacktestError(code, {"field": "selectors"})
    normalized = []
    for selector in selectors:
        if not isinstance(selector, str):
            raise BacktestError(code, {"field": "selectors"})
        value = selector.strip()
        if not value:
            raise BacktestError(code, {"field": "selectors"})
        normalized.append(value)
    values = tuple(sorted(set(normalized)))
    if not values:
        raise BacktestError(code, {"field": "selectors"})
    return values


def _validate_samples(samples: object, code: str) -> list[dict]:
    if isinstance(samples, (str, bytes, dict)) or not isinstance(samples, Iterable):
        raise BacktestError(code, {"field": "samples"})

    validated = []
    seen_ids = set()
    for row in samples:
        if not isinstance(row, dict) or not _SAMPLE_KEYS.issubset(row):
            raise BacktestError(code, {"field": "sample"})

        sample_id = _identifier(row["sample_id"], code, "sample_id")
        if sample_id in seen_ids:
            raise BacktestError(code, {"field": "sample_id", "sample_id": sample_id})
        seen_ids.add(sample_id)

        label = row["label"]
        if label not in SAMPLE_LABELS:
            raise BacktestError(code, {"field": "label"})

        tags = row["tags"]
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            raise BacktestError(code, {"field": "tags"})

        baseline_state = row["baseline_state"]
        if baseline_state not in BASELINE_STATES:
            raise BacktestError(code, {"field": "baseline_state"})

        validated.append({
            "sample_id": sample_id,
            "label": label,
            "tags": list(tags),
            "baseline_state": baseline_state,
        })
    return validated


def _batch_count(total: int, batch_size: int) -> int:
    return (total + batch_size - 1) // batch_size


def _run_view(run: dict) -> dict:
    return {
        "run_id": run["run_id"],
        "status": run["status"],
        "total": run["total"],
        "total_batches": run["total_batches"],
        "next_batch": run["next_batch"],
    }


def _progress_view(run: dict) -> dict:
    result = _run_view(run)
    result.update({
        "processed": run["processed"],
        "candidate_hits": run["candidate_hits"],
        "baseline_hits": run["baseline_hits"],
    })
    return result


def _compare_view(run: dict) -> dict:
    return {
        "scored": run["scored"],
        "candidate_hits": run["candidate_hits"],
        "baseline_hits": run["baseline_hits"],
        "new_hits": run["new_hits"],
        "candidate_fp": run["candidate_fp"],
        "baseline_fp": run["baseline_fp"],
        "fp_delta": run["candidate_fp"] - run["baseline_fp"],
    }


def _decision_view(run: dict) -> dict:
    return copy.deepcopy(run["decision"])


def _sample_values(sample: dict, selectors: set[str]) -> tuple[bool, bool, bool, bool, bool]:
    candidate_hit = not selectors.isdisjoint(sample["tags"])
    baseline_hit = sample["baseline_state"] == "hit"
    new_hit = sample["baseline_state"] == "miss" and candidate_hit
    candidate_fp = sample["label"] == "benign" and candidate_hit
    baseline_fp = sample["label"] == "benign" and baseline_hit
    return candidate_hit, baseline_hit, new_hit, candidate_fp, baseline_fp


class RuleBacktestGate:
    """Load rules and a sample set, replay in batches, compare against the baseline."""

    def __init__(self, *, batch_size: int = 4, max_new_hits: int = 3,
                 max_fp_delta: int = 2) -> None:
        if not _is_positive(batch_size):
            raise BacktestError(ERR_INVALID_CONFIG, {"field": "batch_size"})
        if not _is_int(max_new_hits) or not _is_int(max_fp_delta):
            raise BacktestError(ERR_INVALID_CONFIG, {"field": "threshold"})

        self.batch_size = batch_size
        self.max_new_hits = max_new_hits
        self.max_fp_delta = max_fp_delta
        self._lock = threading.RLock()
        self._baselines: dict[str, dict] = {}
        self._candidates: dict[str, dict] = {}
        self._samplesets: dict[str, dict] = {}
        self._runs: dict[str, dict] = {}
        self._counters = {"next_run": 1, "accepted": 0, "rejected": 0}

    def load_baseline(self, rule_id: str, *, version: int) -> dict:
        with self._lock:
            rule_id = _identifier(rule_id, ERR_INVALID_RULE, "rule_id")
            if not _is_positive(version):
                raise BacktestError(ERR_INVALID_RULE, {"field": "version"})
            record = {"rule_id": rule_id, "version": version}
            self._baselines[rule_id] = record
            return dict(record)

    def load_candidate(self, rule_id: str, *, version: int, selectors) -> dict:
        with self._lock:
            rule_id = _identifier(rule_id, ERR_INVALID_RULE, "rule_id")
            if not _is_positive(version):
                raise BacktestError(ERR_INVALID_RULE, {"field": "version"})
            normalized = _normalize_selectors(selectors, ERR_INVALID_RULE)
            record = {
                "rule_id": rule_id,
                "version": version,
                "selectors": normalized,
            }
            self._candidates[rule_id] = record
            return dict(record)

    def load_samples(self, sampleset_id: str, *, version: int,
                     baseline_version: int, samples) -> dict:
        with self._lock:
            sampleset_id = _identifier(
                sampleset_id, ERR_INVALID_SAMPLES, "sampleset_id")
            if not _is_positive(version):
                raise BacktestError(ERR_INVALID_SAMPLES, {"field": "version"})
            if not _is_positive(baseline_version):
                raise BacktestError(
                    ERR_INVALID_SAMPLES, {"field": "baseline_version"})
            validated = _validate_samples(samples, ERR_INVALID_SAMPLES)
            record = {
                "sampleset_id": sampleset_id,
                "version": version,
                "baseline_version": baseline_version,
                "total": len(validated),
                "samples": validated,
            }
            self._samplesets[sampleset_id] = record
            return {
                "sampleset_id": sampleset_id,
                "version": version,
                "baseline_version": baseline_version,
                "total": len(validated),
            }

    def run_backtest(self, *, candidate: str, baseline: str, sampleset: str,
                     batch_size: int | None = None,
                     batch_limit: int | None = None) -> dict:
        with self._lock:
            candidate_record = self._candidates.get(candidate)
            baseline_record = self._baselines.get(baseline)
            if candidate_record is None or baseline_record is None:
                raise BacktestError(ERR_UNKNOWN_RULE, {
                    "candidate": candidate,
                    "baseline": baseline,
                })

            sampleset_record = self._samplesets.get(sampleset)
            if sampleset_record is None:
                raise BacktestError(ERR_UNKNOWN_SAMPLES, {"sampleset": sampleset})
            if sampleset_record["baseline_version"] != baseline_record["version"]:
                raise BacktestError(ERR_BASELINE_MISMATCH, {
                    "baseline_version": baseline_record["version"],
                    "sampleset_baseline_version":
                        sampleset_record["baseline_version"],
                })

            effective_batch_size = self._batch_size_value(batch_size)
            limit = self._batch_limit_value(batch_limit)
            sequence = self._counters["next_run"]
            run_id = f"BT-{sequence:04d}"
            total = sampleset_record["total"]
            total_batches = _batch_count(total, effective_batch_size)

            run = {
                "run_id": run_id,
                "status": RUN_RUNNING,
                "candidate_id": candidate,
                "baseline_id": baseline,
                "sampleset_id": sampleset,
                "candidate_version": candidate_record["version"],
                "baseline_version": baseline_record["version"],
                "sampleset_version": sampleset_record["version"],
                "batch_size": effective_batch_size,
                "candidate_selectors": candidate_record["selectors"],
                "samples": copy.deepcopy(sampleset_record["samples"]),
                "total": total,
                "total_batches": total_batches,
                "next_batch": 0,
                "processed": 0,
                "candidate_hits": 0,
                "baseline_hits": 0,
                "scored": 0,
                "new_hits": 0,
                "candidate_fp": 0,
                "baseline_fp": 0,
                "batches": [],
                "decision": None,
            }
            self._runs[run_id] = run
            self._counters["next_run"] = sequence + 1
            self._execute(run, limit)
            return _run_view(run)

    def interrupt(self, run_id: str) -> dict:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise BacktestError(ERR_UNKNOWN_RUN, {"run_id": run_id})
            if run["status"] not in (RUN_PAUSED, RUN_INTERRUPTED):
                raise BacktestError(ERR_RUN_STATE, {"run_id": run_id,
                                                   "status": run["status"]})
            run["status"] = RUN_INTERRUPTED
            return _run_view(run)

    def resume(self, run_id: str, *, batch_limit: int | None = None) -> dict:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise BacktestError(ERR_UNKNOWN_RUN, {"run_id": run_id})
            if run["status"] not in (RUN_PAUSED, RUN_INTERRUPTED):
                raise BacktestError(ERR_RUN_STATE, {"run_id": run_id,
                                                   "status": run["status"]})
            self._execute(run, self._batch_limit_value(batch_limit))
            return _run_view(run)

    def progress(self, run_id: str) -> dict:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise BacktestError(ERR_UNKNOWN_RUN, {"run_id": run_id})
            return _progress_view(run)

    def compare_baseline(self, run_id: str) -> dict:
        with self._lock:
            run = self._run_for_result(run_id)
            return _compare_view(run)

    def decide(self, run_id: str) -> dict:
        with self._lock:
            run = self._run_for_result(run_id)
            if run["decision"] is not None:
                return _decision_view(run)

            fp_delta = run["candidate_fp"] - run["baseline_fp"]
            reasons = []
            if run["new_hits"] > self.max_new_hits:
                reasons.append(REASON_NEW_HITS)
            if fp_delta > self.max_fp_delta:
                reasons.append(REASON_FP_DELTA)
            verdict = VERDICT_REJECT if reasons else VERDICT_ACCEPT
            decision = {
                "run_id": run_id,
                "verdict": verdict,
                "reasons": tuple(reasons),
                "candidate_version": run["candidate_version"],
                "baseline_version": run["baseline_version"],
                "sampleset_version": run["sampleset_version"],
                "new_hits": run["new_hits"],
                "fp_delta": fp_delta,
            }
            run["decision"] = decision
            if verdict == VERDICT_ACCEPT:
                self._counters["accepted"] += 1
            else:
                self._counters["rejected"] += 1
            return copy.deepcopy(decision)

    def report(self, run_id: str) -> dict:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise BacktestError(ERR_UNKNOWN_RUN, {"run_id": run_id})
            result = _progress_view(run)
            result.update({
                "candidate_id": run["candidate_id"],
                "baseline_id": run["baseline_id"],
                "sampleset_id": run["sampleset_id"],
                "candidate_version": run["candidate_version"],
                "baseline_version": run["baseline_version"],
                "sampleset_version": run["sampleset_version"],
                "scored": run["scored"],
                "new_hits": run["new_hits"],
                "candidate_fp": run["candidate_fp"],
                "baseline_fp": run["baseline_fp"],
                "fp_delta": run["candidate_fp"] - run["baseline_fp"],
                "batches": copy.deepcopy(run["batches"]),
                "decision": copy.deepcopy(run["decision"]),
            })
            return result

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "format": _SNAPSHOT_FORMAT,
                "baselines": self._baselines,
                "candidates": self._candidates,
                "samplesets": self._samplesets,
                "runs": self._runs,
                "counters": self._counters,
            })

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._parse_snapshot(state)
                self._merge_completed_runs(restored)
            except BacktestError as exc:
                if exc.code == ERR_SNAPSHOT_INVALID:
                    raise
                raise BacktestError(
                    ERR_SNAPSHOT_INVALID, {"reason": str(exc.detail)}) from None
            except Exception as exc:
                raise BacktestError(
                    ERR_SNAPSHOT_INVALID, {"reason": str(exc)}) from None

            self._baselines = restored["baselines"]
            self._candidates = restored["candidates"]
            self._samplesets = restored["samplesets"]
            self._runs = restored["runs"]
            self._counters = restored["counters"]

    def stats(self) -> dict:
        with self._lock:
            return {
                "baselines": len(self._baselines),
                "candidates": len(self._candidates),
                "samplesets": len(self._samplesets),
                "runs": len(self._runs),
                "accepted": self._counters["accepted"],
                "rejected": self._counters["rejected"],
            }

    def _batch_size_value(self, batch_size: int | None) -> int:
        if batch_size is None:
            return self.batch_size
        if not _is_positive(batch_size):
            raise BacktestError(ERR_INVALID_BATCH, {"field": "batch_size"})
        return batch_size

    def _batch_limit_value(self, batch_limit: int | None) -> int | None:
        if batch_limit is None:
            return None
        if not _is_int(batch_limit) or batch_limit < 0:
            raise BacktestError(ERR_INVALID_BATCH, {"field": "batch_limit"})
        return batch_limit

    def _run_for_result(self, run_id: str) -> dict:
        run = self._runs.get(run_id)
        if run is None:
            raise BacktestError(ERR_UNKNOWN_RUN, {"run_id": run_id})
        if run["status"] != RUN_COMPLETED:
            raise BacktestError(ERR_RUN_NOT_READY, {
                "run_id": run_id,
                "status": run["status"],
            })
        return run

    def _execute(self, run: dict, batch_limit: int | None) -> None:
        remaining = run["total_batches"] - run["next_batch"]
        count = remaining if batch_limit is None else min(batch_limit, remaining)
        selectors = set(run["candidate_selectors"])
        batch_size = run["batch_size"]

        for batch_index in range(run["next_batch"],
                                 run["next_batch"] + count):
            start = batch_index * batch_size
            end = min(start + batch_size, run["total"])
            batch_candidate_hits = 0

            for sample in run["samples"][start:end]:
                (candidate_hit, baseline_hit, new_hit,
                 candidate_fp, baseline_fp) = _sample_values(sample, selectors)
                run["processed"] += 1
                if candidate_hit:
                    run["candidate_hits"] += 1
                    batch_candidate_hits += 1
                if baseline_hit:
                    run["baseline_hits"] += 1
                if sample["baseline_state"] != "absent":
                    run["scored"] += 1
                if new_hit:
                    run["new_hits"] += 1
                if candidate_fp:
                    run["candidate_fp"] += 1
                if baseline_fp:
                    run["baseline_fp"] += 1

            run["batches"].append({
                "batch_no": batch_index + 1,
                "processed": end - start,
                "candidate_hits": batch_candidate_hits,
            })
            run["next_batch"] = batch_index + 1

        if run["next_batch"] == run["total_batches"]:
            run["status"] = RUN_COMPLETED
        else:
            run["status"] = RUN_PAUSED

    def _parse_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "snapshot"})
        if state["format"] != _SNAPSHOT_FORMAT:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "format"})

        raw_baselines = self._mapping(state["baselines"], "baselines")
        baselines = {}
        for rule_id, record in raw_baselines.items():
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "baselines"})
            if not isinstance(record, dict) or set(record) != _BASE_KEYS:
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "baselines"})
            if record["rule_id"] != rule_id or not _is_positive(record["version"]):
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "baselines"})
            baselines[rule_id] = copy.deepcopy(record)

        raw_candidates = self._mapping(state["candidates"], "candidates")
        candidates = {}
        for rule_id, record in raw_candidates.items():
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "candidates"})
            if not isinstance(record, dict) or set(record) != _CANDIDATE_KEYS:
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "candidates"})
            if record["rule_id"] != rule_id or not _is_positive(record["version"]):
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "candidates"})
            selectors = _normalize_selectors(
                record["selectors"], ERR_SNAPSHOT_INVALID)
            candidates[rule_id] = {
                "rule_id": rule_id,
                "version": record["version"],
                "selectors": selectors,
            }

        raw_samplesets = self._mapping(state["samplesets"], "samplesets")
        samplesets = {}
        for sampleset_id, record in raw_samplesets.items():
            if not isinstance(sampleset_id, str) or not sampleset_id.strip():
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "samplesets"})
            if not isinstance(record, dict) or set(record) != _SAMPLESET_KEYS:
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "samplesets"})
            if (record["sampleset_id"] != sampleset_id
                    or not _is_positive(record["version"])
                    or not _is_positive(record["baseline_version"])):
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "samplesets"})
            samples = _validate_samples(
                record["samples"], ERR_SNAPSHOT_INVALID)
            if not _is_int(record["total"]) or record["total"] != len(samples):
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "samplesets"})
            samplesets[sampleset_id] = {
                "sampleset_id": sampleset_id,
                "version": record["version"],
                "baseline_version": record["baseline_version"],
                "total": len(samples),
                "samples": samples,
            }

        raw_runs = self._mapping(state["runs"], "runs")
        runs = {}
        for run_id, record in raw_runs.items():
            runs[run_id] = self._parse_snapshot_run(
                run_id, record, baselines, candidates, samplesets)

        counters = self._parse_snapshot_counters(state["counters"])
        self._validate_snapshot_runs(runs, counters)
        return {
            "baselines": baselines,
            "candidates": candidates,
            "samplesets": samplesets,
            "runs": runs,
            "counters": counters,
        }

    def _parse_snapshot_run(self, run_id: str, record: object,
                            baselines: dict, candidates: dict,
                            samplesets: dict) -> dict:
        if not isinstance(run_id, str) or not run_id.startswith("BT-"):
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs"})
        if not isinstance(record, dict) or set(record) != _RUN_KEYS:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs"})
        if record["run_id"] != run_id:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs"})
        if record["status"] not in (RUN_PAUSED, RUN_INTERRUPTED, RUN_COMPLETED):
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs"})

        candidate_id = record["candidate_id"]
        baseline_id = record["baseline_id"]
        sampleset_id = record["sampleset_id"]
        if candidate_id not in candidates or baseline_id not in baselines:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs"})
        if sampleset_id not in samplesets:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs"})

        for field in ("candidate_version", "baseline_version",
                      "sampleset_version", "batch_size"):
            if not _is_positive(record[field]):
                raise BacktestError(
                    ERR_SNAPSHOT_INVALID, {"field": f"runs.{field}"})

        selectors = _normalize_selectors(
            record["candidate_selectors"], ERR_SNAPSHOT_INVALID)
        samples = _validate_samples(
            record["samples"], ERR_SNAPSHOT_INVALID)
        if not _is_int(record["total"]) or record["total"] != len(samples):
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs.total"})

        total_batches = _batch_count(record["total"], record["batch_size"])
        if (not _is_int(record["total_batches"])
                or record["total_batches"] != total_batches):
            raise BacktestError(
                ERR_SNAPSHOT_INVALID, {"field": "runs.total_batches"})
        if (not _is_int(record["next_batch"])
                or not 0 <= record["next_batch"] <= total_batches):
            raise BacktestError(
                ERR_SNAPSHOT_INVALID, {"field": "runs.next_batch"})

        recomputed = self._recompute_run_progress(
            samples, selectors, record["batch_size"], record["next_batch"])
        integer_fields = (
            "processed", "candidate_hits", "baseline_hits", "scored",
            "new_hits", "candidate_fp", "baseline_fp",
        )
        for field in integer_fields:
            if not _is_int(record[field]) or record[field] != recomputed[field]:
                raise BacktestError(
                    ERR_SNAPSHOT_INVALID, {"field": f"runs.{field}"})
        if record["batches"] != recomputed["batches"]:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs.batches"})

        if record["status"] == RUN_COMPLETED:
            if (record["next_batch"] != total_batches
                    or record["processed"] != record["total"]):
                raise BacktestError(
                    ERR_SNAPSHOT_INVALID, {"field": "runs.status"})
        elif (record["next_batch"] >= total_batches
              or record["processed"] >= record["total"]):
            raise BacktestError(
                ERR_SNAPSHOT_INVALID, {"field": "runs.status"})

        decision = self._parse_snapshot_decision(
            run_id, record["decision"], record)
        if decision is not None and record["status"] != RUN_COMPLETED:
            raise BacktestError(
                ERR_SNAPSHOT_INVALID, {"field": "runs.decision"})

        result = copy.deepcopy(record)
        result["candidate_selectors"] = selectors
        result["samples"] = samples
        result["decision"] = decision
        return result

    def _recompute_run_progress(self, samples: list[dict],
                                selectors: tuple[str, ...],
                                batch_size: int, next_batch: int) -> dict:
        selector_set = set(selectors)
        values = {
            "processed": 0,
            "candidate_hits": 0,
            "baseline_hits": 0,
            "scored": 0,
            "new_hits": 0,
            "candidate_fp": 0,
            "baseline_fp": 0,
            "batches": [],
        }
        for batch_index in range(next_batch):
            start = batch_index * batch_size
            end = min(start + batch_size, len(samples))
            batch_candidate_hits = 0
            for sample in samples[start:end]:
                (candidate_hit, baseline_hit, new_hit,
                 candidate_fp, baseline_fp) = _sample_values(sample, selector_set)
                values["processed"] += 1
                if candidate_hit:
                    values["candidate_hits"] += 1
                    batch_candidate_hits += 1
                if baseline_hit:
                    values["baseline_hits"] += 1
                if sample["baseline_state"] != "absent":
                    values["scored"] += 1
                if new_hit:
                    values["new_hits"] += 1
                if candidate_fp:
                    values["candidate_fp"] += 1
                if baseline_fp:
                    values["baseline_fp"] += 1
            values["batches"].append({
                "batch_no": batch_index + 1,
                "processed": end - start,
                "candidate_hits": batch_candidate_hits,
            })
        return values

    def _parse_snapshot_decision(self, run_id: str, value: object,
                                 run_record: dict) -> dict | None:
        if value is None:
            return None
        expected_keys = {
            "run_id", "verdict", "reasons", "candidate_version",
            "baseline_version", "sampleset_version", "new_hits", "fp_delta",
        }
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs.decision"})
        if value["run_id"] != run_id:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs.decision"})
        if value["verdict"] not in (VERDICT_ACCEPT, VERDICT_REJECT):
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs.decision"})
        for field in ("candidate_version", "baseline_version",
                      "sampleset_version"):
            if value[field] != run_record[field]:
                raise BacktestError(
                    ERR_SNAPSHOT_INVALID, {"field": "runs.decision"})
        if (not _is_int(value["new_hits"])
                or value["new_hits"] != run_record["new_hits"]
                or not _is_int(value["fp_delta"])
                or value["fp_delta"] != (run_record["candidate_fp"]
                                         - run_record["baseline_fp"])):
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs.decision"})

        reasons = value["reasons"]
        if not isinstance(reasons, (list, tuple)):
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs.decision"})
        valid_sequence = (
            (),
            (REASON_NEW_HITS,),
            (REASON_FP_DELTA,),
            (REASON_NEW_HITS, REASON_FP_DELTA),
        )
        if tuple(reasons) not in valid_sequence:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs.decision"})
        if (value["verdict"] == VERDICT_ACCEPT) != (not reasons):
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs.decision"})

        result = copy.deepcopy(value)
        result["reasons"] = tuple(reasons)
        return result

    def _parse_snapshot_counters(self, value: object) -> dict:
        counters = self._mapping(value, "counters")
        if set(counters) != _COUNTER_KEYS:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "counters"})
        for field in _COUNTER_KEYS:
            if not _is_int(counters[field]) or counters[field] < 0:
                raise BacktestError(
                    ERR_SNAPSHOT_INVALID, {"field": f"counters.{field}"})
        return dict(counters)

    def _validate_snapshot_runs(self, runs: dict, counters: dict) -> None:
        sequences = []
        for run_id in runs:
            suffix = run_id[3:]
            if not suffix.isdigit() or int(suffix) <= 0:
                raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs"})
            sequences.append(int(suffix))
        sequences.sort()
        if sequences != list(range(1, len(runs) + 1)):
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "runs"})
        if counters["next_run"] != len(runs) + 1:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "counters"})

        accepted = sum(
            1 for run in runs.values()
            if run["decision"] is not None
            and run["decision"]["verdict"] == VERDICT_ACCEPT)
        rejected = sum(
            1 for run in runs.values()
            if run["decision"] is not None
            and run["decision"]["verdict"] == VERDICT_REJECT)
        if counters["accepted"] != accepted or counters["rejected"] != rejected:
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": "counters"})

    def _merge_completed_runs(self, restored: dict) -> None:
        restored_runs = restored["runs"]
        merged_current_runs = False
        for run_id, current in self._runs.items():
            if current["status"] != RUN_COMPLETED:
                continue
            restored_run = restored_runs.get(run_id)
            if (restored_run is None
                    or restored_run["status"] != RUN_COMPLETED
                    or (current["decision"] is not None
                        and restored_run["decision"] != current["decision"])):
                restored_runs[run_id] = copy.deepcopy(current)
                merged_current_runs = True

        if not merged_current_runs:
            return

        for run_id, run in restored_runs.items():
            if run["candidate_id"] not in restored["candidates"]:
                restored["candidates"][run["candidate_id"]] = copy.deepcopy(
                    self._candidates[run["candidate_id"]])
            if run["baseline_id"] not in restored["baselines"]:
                restored["baselines"][run["baseline_id"]] = copy.deepcopy(
                    self._baselines[run["baseline_id"]])
            if run["sampleset_id"] not in restored["samplesets"]:
                restored["samplesets"][run["sampleset_id"]] = copy.deepcopy(
                    self._samplesets[run["sampleset_id"]])

        restored["counters"]["next_run"] = len(restored_runs) + 1
        restored["counters"]["accepted"] = sum(
            1 for run in restored_runs.values()
            if run["decision"] is not None
            and run["decision"]["verdict"] == VERDICT_ACCEPT)
        restored["counters"]["rejected"] = sum(
            1 for run in restored_runs.values()
            if run["decision"] is not None
            and run["decision"]["verdict"] == VERDICT_REJECT)
        self._validate_snapshot_runs(restored_runs, restored["counters"])

    @staticmethod
    def _mapping(value: object, field: str) -> dict:
        if not isinstance(value, dict):
            raise BacktestError(ERR_SNAPSHOT_INVALID, {"field": field})
        return value
