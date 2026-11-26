import copy
import threading

import pytest

import time_trial_ghost_ledger as tl

FULL_MASK = 0b1111


def ledger(**kwargs):
    options = {"checkpoint_count": 4, "max_samples": 64}
    options.update(kwargs)
    return tl.TimeTrialLedger(**options)


def begin(board, player="p1", track="t1"):
    return board.start_run(player, track_id=track)


def complete(board, finish_ms=7000, player="p1", track="t1"):
    times = (1000, 2500, 4000, 6000)
    begin(board, player=player, track=track)
    for index, at_ms in enumerate(times):
        board.checkpoint(index, at_ms=at_ms)
    return board.finish_run(at_ms=finish_ms)


def test_start_run_opens_one_active_run():
    board = ledger()
    run = begin(board)
    assert run["player"] == "p1"
    assert run["track_id"] == "t1"
    assert run["mask"] == 0
    assert run["next_index"] == 0
    assert board.checkpoint_mask() == 0
    with pytest.raises(tl.TrialError) as exc:
        begin(board)
    assert exc.value.code == "TRIAL_RUN_ACTIVE"
    assert board.stats()["runs_started"] == 1


def test_checkpoints_in_order_record_splits_and_mask():
    board = ledger()
    begin(board)
    first = board.checkpoint(0, at_ms=1000)
    assert first["split_ms"] == 1000
    assert first["mask"] == 0b0001
    assert first["next_index"] == 1
    second = board.checkpoint(1, at_ms=3000)
    assert second["split_ms"] == 2000
    assert second["mask"] == 0b0011
    assert second["total_ms"] == 3000
    assert board.checkpoint_mask() == 0b0011
    assert board.elapsed_ms() == 3000
    assert board.current_run()["next_index"] == 2


def test_checkpoint_index_out_of_range_is_rejected():
    board = ledger()
    begin(board)
    for index in (-1, 4, 1.5):
        with pytest.raises(tl.TrialError) as exc:
            board.checkpoint(index, at_ms=500)
        assert exc.value.code == "TRIAL_INVALID_REQUEST"
    assert board.checkpoint(0, at_ms=800)["mask"] == 1


def test_shortcut_invalidates_the_run():
    board = ledger()
    begin(board)
    board.checkpoint(0, at_ms=1000)
    with pytest.raises(tl.TrialError) as exc:
        board.checkpoint(2, at_ms=2000)
    assert exc.value.code == "TRIAL_SHORTCUT"
    assert board.current_run()["invalid"] is True
    assert board.stats()["invalidated"] == 1
    with pytest.raises(tl.TrialError) as exc:
        board.finish_run(at_ms=3000)
    assert exc.value.code == "TRIAL_RUN_INVALID"


def test_checkpoint_without_active_run_is_rejected():
    board = ledger()
    with pytest.raises(tl.TrialError) as exc:
        board.checkpoint(0, at_ms=100)
    assert exc.value.code == "TRIAL_NO_ACTIVE_RUN"
    assert board.current_run() is None


def test_finish_requires_the_full_checkpoint_mask():
    board = ledger()
    begin(board)
    board.checkpoint(0, at_ms=1000)
    with pytest.raises(tl.TrialError) as exc:
        board.finish_run(at_ms=2000)
    assert exc.value.code == "TRIAL_INCOMPLETE"
    assert board.current_run() is not None
    board.checkpoint(1, at_ms=2500)
    board.checkpoint(2, at_ms=4000)
    board.checkpoint(3, at_ms=6000)
    lap = board.finish_run(at_ms=7000)
    assert lap.total_ms == 7000


def test_finish_returns_lap_with_splits_and_mask():
    board = ledger()
    lap = complete(board)
    assert lap.total_ms == 7000
    assert lap.splits_ms == (1000, 1500, 1500, 2000)
    assert lap.checkpoint_mask == FULL_MASK
    assert lap.valid is True
    assert lap.player == "p1"
    assert lap.track_id == "t1"
    assert board.stats()["laps_finished"] == 1
    assert board.current_run() is None


def test_finish_twice_is_refused():
    board = ledger()
    complete(board)
    with pytest.raises(tl.TrialError) as exc:
        board.finish_run(at_ms=9000)
    assert exc.value.code == "TRIAL_NO_ACTIVE_RUN"


def test_submit_places_lap_on_the_leaderboard():
    board = ledger()
    lap = complete(board)
    outcome = board.submit(lap)
    assert outcome["accepted"] is True
    assert outcome["rank"] == 1
    assert board.validate(lap.lap_id)["valid"] is True
    board_view = board.leaderboard(track_id="t1")
    assert len(board_view) == 1
    assert board_view[0]["player"] == "p1"
    assert board_view[0]["total_ms"] == 7000
    assert board_view[0]["rank"] == 1


def test_slower_lap_does_not_replace_the_best():
    board = ledger()
    fast = complete(board, finish_ms=5000)
    board.submit(fast)
    slow = complete(board, finish_ms=6000)
    outcome = board.submit(slow)
    assert outcome["accepted"] is False
    board_view = board.leaderboard(track_id="t1")
    assert len(board_view) == 1
    assert board_view[0]["total_ms"] == 5000
    best = board.best_of("p1")
    assert best["total_ms"] == 5000
    assert best["lap_id"] == fast.lap_id


def test_submit_rejects_mask_mismatch():
    board = ledger()
    lap = complete(board)
    tampered = tl.LapRecord(
        lap_id=lap.lap_id,
        player=lap.player,
        track_id=lap.track_id,
        total_ms=lap.total_ms,
        splits_ms=lap.splits_ms,
        checkpoint_mask=0b1011,
        valid=True,
        finished_seq=lap.finished_seq,
    )
    with pytest.raises(tl.TrialError) as exc:
        board.submit(tampered)
    assert exc.value.code == "TRIAL_MASK_MISMATCH"
    assert board.leaderboard(track_id="t1") == ()


def test_ghost_samples_are_capped_and_ordered():
    board = ledger()
    lap = complete(board)
    samples = board.ghost_samples(lap.lap_id, max_samples=3)
    assert 1 <= len(samples) <= 3
    assert samples[0][0] == 0
    times = [sample[0] for sample in samples]
    assert times == sorted(times)
    assert all(isinstance(sample[1], int) for sample in samples)


def test_snapshot_restore_roundtrip_keeps_run_and_best():
    board = ledger()
    lap = complete(board, finish_ms=5000)
    board.submit(lap)
    begin(board)
    board.checkpoint(0, at_ms=1200)
    state = board.snapshot()
    detached = copy.deepcopy(state)
    state["stats"]["submitted"] = 99

    clone = ledger()
    clone.restore(detached)
    assert clone.checkpoint_mask() == 0b0001
    assert clone.elapsed_ms() == 1200
    assert clone.best_of("p1")["total_ms"] == 5000
    assert board.stats()["submitted"] == 1
    clone.checkpoint(1, at_ms=2400)
    assert clone.checkpoint_mask() == 0b0011


def test_restore_rejects_malformed_state_and_keeps_live_run():
    board = ledger()
    begin(board)
    board.checkpoint(0, at_ms=1000)
    bad_states = [
        None,
        {},
        {"version": 2, "run": None, "laps": [], "board": {}, "stats": {}},
        {"version": 1, "run": "nope", "laps": [], "board": {}, "stats": {}},
        {"version": 1, "run": None, "laps": [], "board": [], "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(tl.TrialError) as exc:
            board.restore(bad)
        assert exc.value.code == "TRIAL_SNAPSHOT_INVALID"
    assert board.checkpoint_mask() == 1
    assert board.current_run() is not None


def test_concurrent_submissions_keep_the_fastest_lap():
    board = ledger()
    times = [5200, 4800, 6100, 4400, 5700, 5000]
    errors = []
    accepted = []
    barrier = threading.Barrier(len(times))

    def worker(index, total):
        barrier.wait(timeout=5)
        lap = tl.LapRecord(
            lap_id=f"lap-{index}",
            player="p1",
            track_id="t1",
            total_ms=total,
            splits_ms=(1000, 1500, 1500, total - 4000),
            checkpoint_mask=FULL_MASK,
            valid=True,
            finished_seq=index,
        )
        try:
            accepted.append(board.submit(lap))
        except Exception as exc:  # noqa: BLE001 - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index, total))
               for index, total in enumerate(times)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(accepted) == len(times)
    board_view = board.leaderboard(track_id="t1")
    assert len(board_view) == 1
    assert board_view[0]["total_ms"] == min(times)
    assert board.best_of("p1")["total_ms"] == min(times)
