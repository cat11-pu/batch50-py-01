"""Replay gate that scores a candidate detection rule against a historical sample set."""

from __future__ import annotations


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


class RuleBacktestGate:
    """Load rules and a sample set, replay in batches, compare against the baseline."""

    def __init__(self, *, batch_size: int = 4, max_new_hits: int = 3,
                 max_fp_delta: int = 2) -> None:
        self.batch_size = batch_size
        self.max_new_hits = max_new_hits
        self.max_fp_delta = max_fp_delta

    def load_baseline(self, rule_id: str, *, version: int) -> dict:
        raise NotImplementedError

    def load_candidate(self, rule_id: str, *, version: int, selectors) -> dict:
        raise NotImplementedError

    def load_samples(self, sampleset_id: str, *, version: int,
                     baseline_version: int, samples) -> dict:
        raise NotImplementedError

    def run_backtest(self, *, candidate: str, baseline: str, sampleset: str,
                     batch_size: int | None = None,
                     batch_limit: int | None = None) -> dict:
        raise NotImplementedError

    def interrupt(self, run_id: str) -> dict:
        raise NotImplementedError

    def resume(self, run_id: str, *, batch_limit: int | None = None) -> dict:
        raise NotImplementedError

    def progress(self, run_id: str) -> dict:
        raise NotImplementedError

    def compare_baseline(self, run_id: str) -> dict:
        raise NotImplementedError

    def decide(self, run_id: str) -> dict:
        raise NotImplementedError

    def report(self, run_id: str) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
