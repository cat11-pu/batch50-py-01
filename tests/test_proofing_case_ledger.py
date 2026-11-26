import threading

import pytest

import proofing_case_ledger as pl

BASE = 1_800_000_000


def ledger(**kwargs):
    return pl.ProofingCaseLedger(**kwargs)


def opened(led, applicant="app-1", digest="doc-aaa", now=BASE):
    return led.open(applicant, digest, now=now)


def ready_case(led, *, applicant="app-1", digest="doc-aaa", now=BASE):
    case = opened(led, applicant=applicant, digest=digest, now=now)
    led.attempt(case.case_id, "document", "mat-d", "pass", now=now + 1)
    led.attempt(case.case_id, "liveness", "mat-l", "pass", now=now + 2)
    return case.case_id


def code_of(exc_info):
    return exc_info.value.code


def test_open_case_creates_collecting_case():
    led = ledger()
    rec = opened(led)
    assert rec.case_id == "case-1"
    assert rec.state == "collecting"
    assert led.stats()["opened"] == 1
    assert led.stats()["merged"] == 0
    assert led.stats()["attempts"] == 0
    assert led.stats()["refused"] == 0


def test_reopening_same_applicant_merges_without_new_case():
    led = ledger()
    first = opened(led)
    second = opened(led, digest="doc-other", now=BASE + 5)
    assert second.case_id == first.case_id
    assert led.stats()["opened"] == 1
    assert led.stats()["merged"] == 1
    assert led.queue() == []


def test_open_case_rejects_blank_inputs():
    led = ledger()
    with pytest.raises(pl.ProofingError) as first:
        led.open("", "doc-aaa", now=BASE)
    assert code_of(first) == "PROOF_INVALID"
    with pytest.raises(pl.ProofingError) as second:
        led.open("app-1", "   ", now=BASE)
    assert code_of(second) == "PROOF_INVALID"
    assert led.stats()["opened"] == 0


def test_pass_attempt_is_counted_and_keeps_case_collecting():
    led = ledger()
    case = opened(led)
    rec = led.attempt(case.case_id, "document", "mat-d", "pass", now=BASE + 3)
    assert rec.window == 1
    assert led.stats()["attempts"] == 1
    assert led.stats()["refused"] == 0
    assert led.view(case.case_id).state == "collecting"


def test_two_passes_mark_ready_and_queue_orders_by_ready_time():
    led = ledger()
    late = opened(led, applicant="app-a", digest="doc-a")
    early = opened(led, applicant="app-b", digest="doc-b")
    led.attempt(late.case_id, "document", "m1", "pass", now=BASE + 1)
    led.attempt(early.case_id, "document", "m2", "pass", now=BASE + 1)
    led.attempt(early.case_id, "liveness", "m3", "pass", now=BASE + 2)
    assert led.view(early.case_id).state == "ready"
    assert led.view(early.case_id).ready_at == BASE + 2
    led.attempt(late.case_id, "liveness", "m4", "pass", now=BASE + 9)
    assert led.view(late.case_id).state == "ready"
    assert led.queue() == [early.case_id, late.case_id]
    assert led.queue(now=BASE + 99) == [early.case_id, late.case_id]


def test_unknown_case_is_refused():
    led = ledger()
    with pytest.raises(pl.ProofingError) as first:
        led.attempt("case-999", "document", "m", "pass", now=BASE)
    assert code_of(first) == "PROOF_UNKNOWN"
    with pytest.raises(pl.ProofingError) as second:
        led.view("case-999")
    assert code_of(second) == "PROOF_UNKNOWN"


def test_failure_budget_blocks_then_resets_after_cooldown():
    led = ledger()
    case = opened(led)
    led.attempt(case.case_id, "document", "f1", "fail", now=BASE + 10)
    led.attempt(case.case_id, "document", "f2", "fail", now=BASE + 20)
    led.attempt(case.case_id, "document", "f3", "fail", now=BASE + 30)
    assert led.budget(case.case_id, "document", now=BASE + 31) == 0
    assert led.budget(case.case_id, "liveness", now=BASE + 31) == 3
    with pytest.raises(pl.ProofingError) as blocked:
        led.attempt(case.case_id, "document", "f4", "fail", now=BASE + 40)
    assert code_of(blocked) == "PROOF_BUDGET"
    assert led.stats()["refused"] == 1
    assert led.budget(case.case_id, "document", now=BASE + 629) == 0
    assert led.budget(case.case_id, "document", now=BASE + 630) == 3


def test_assign_grants_lease_and_empties_queue():
    led = ledger()
    case_id = ready_case(led)
    lease = led.assign(case_id, "rev-a", now=BASE + 10)
    assert lease.granted_at == BASE + 10
    assert lease.expires_at == BASE + 310
    assert lease.generation == 1
    assert led.view(case_id).state == "in_review"
    assert led.queue() == []
    assert led.stats()["assigned"] == 1


def test_second_assignment_while_lease_live_is_refused():
    led = ledger()
    case_id = ready_case(led)
    led.assign(case_id, "rev-a", now=BASE + 10)
    with pytest.raises(pl.ProofingError) as held:
        led.assign(case_id, "rev-b", now=BASE + 20)
    assert code_of(held) == "PROOF_LEASE"
    assert led.stats()["assigned"] == 1


def test_assign_before_both_attempts_pass_is_refused():
    led = ledger()
    case = opened(led)
    led.attempt(case.case_id, "document", "m", "pass", now=BASE)
    with pytest.raises(pl.ProofingError) as wrong_state:
        led.assign(case.case_id, "rev-a", now=BASE + 1)
    assert code_of(wrong_state) == "PROOF_STATE"


def test_decision_is_final_and_repeat_is_refused():
    led = ledger()
    case_id = ready_case(led)
    led.assign(case_id, "rev-a", now=BASE + 10)
    first = led.decide(case_id, "rev-a", "approve", "材料一致", now=BASE + 30)
    assert first.state == "decided"
    assert first.decided_by == "rev-a"
    assert first.decided_at == BASE + 30
    with pytest.raises(pl.ProofingError) as final:
        led.decide(case_id, "rev-a", "reject", "改主意", now=BASE + 40)
    assert code_of(final) == "PROOF_FINAL"
    assert led.view(case_id).state == "decided"
    assert led.stats()["decided"] == 1


def test_decision_rejects_bad_verdict_and_blank_reason():
    led = ledger()
    case_id = ready_case(led)
    led.assign(case_id, "rev-a", now=BASE + 10)
    with pytest.raises(pl.ProofingError) as verdict:
        led.decide(case_id, "rev-a", "maybe", "看起来还行", now=BASE + 20)
    assert code_of(verdict) == "PROOF_INVALID"
    with pytest.raises(pl.ProofingError) as reason:
        led.decide(case_id, "rev-a", "approve", "   ", now=BASE + 21)
    assert code_of(reason) == "PROOF_INVALID"
    assert led.view(case_id).state == "in_review"
    assert led.stats()["decided"] == 0


def test_expired_lease_is_reclaimed_and_reassigned_with_next_generation():
    led = ledger()
    case_id = ready_case(led)
    led.assign(case_id, "rev-a", now=BASE + 10)
    assert led.reclaim(case_id, now=BASE + 309) is None
    assert led.view(case_id).state == "in_review"
    reclaimed = led.reclaim(case_id, now=BASE + 310)
    assert reclaimed.generation == 1
    assert led.view(case_id).state == "ready"
    assert led.queue() == [case_id]
    second = led.assign(case_id, "rev-b", now=BASE + 400)
    assert second.generation == 2
    assert second.expires_at == BASE + 700
    assert led.stats()["reclaimed"] == 1


def test_snapshot_restore_keeps_queue_lease_and_remaining_time():
    led = ledger()
    first = ready_case(led, applicant="app-a", digest="doc-a")
    second = ready_case(led, applicant="app-b", digest="doc-b")
    led.assign(second, "rev-a", now=BASE + 20)
    cloned = pl.ProofingCaseLedger()
    cloned.restore(led.snapshot())
    assert cloned.view(first).state == "ready"
    assert cloned.view(second).state == "in_review"
    assert cloned.queue() == [first]
    assert cloned.stats() == led.stats()
    assert cloned.reclaim(second, now=BASE + 319) is None
    assert cloned.reclaim(second, now=BASE + 320).generation == 1
    with pytest.raises(pl.ProofingError) as broken:
        led.restore({"version": 1, "cases": "nope"})
    assert code_of(broken) == "PROOF_SNAPSHOT"
    assert led.view(first).state == "ready"
    assert led.queue() == [first]


def test_concurrent_failing_attempts_never_exceed_budget():
    led = ledger()
    case = opened(led)
    accepted = []
    refused = []
    guard = threading.Lock()

    def worker(index):
        try:
            led.attempt(case.case_id, "document", "d%d" % index, "fail",
                        now=BASE + 5)
        except Exception as err:  # noqa: BLE001 - collect refusal reason
            with guard:
                refused.append(getattr(err, "code", type(err).__name__))
        else:
            with guard:
                accepted.append(index)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(accepted) == 3
    assert refused.count("PROOF_BUDGET") == 5
    assert led.stats()["attempts"] == 3
    assert led.budget(case.case_id, "document", now=BASE + 6) == 0
