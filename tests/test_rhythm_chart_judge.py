import copy
import threading

import pytest

import rhythm_chart_judge as rc

CHART = [
    {"note_id": "n1", "time_ms": 500, "lane": 0, "kind": "tap"},
    {"note_id": "n2", "time_ms": 1000, "lane": 0, "kind": "tap"},
    {"note_id": "n3", "time_ms": 1500, "lane": 1, "kind": "hold", "duration_ms": 500},
    {"note_id": "n4", "time_ms": 2500, "lane": 0, "kind": "tap"},
]


def judge(**kwargs):
    instance = rc.RhythmChartJudge(**kwargs)
    instance.load_chart([dict(note) for note in CHART])
    return instance


def test_load_chart_keeps_order_and_pending_state():
    instance = judge()
    assert instance.results()["notes"] == 4
    assert instance.results()["judged"] == 0
    state = instance.judge("n1")
    assert state.note_id == "n1"
    assert state.status == "pending"
    assert state.judgement is None
    assert state.delta_ms is None
    assert instance.combo() == 0


def test_load_chart_rejects_duplicates_and_unsorted_notes():
    instance = rc.RhythmChartJudge()
    bad_charts = [
        [],
        [{"note_id": "n1", "time_ms": 100, "lane": 0, "kind": "tap"}],
        [
            {"note_id": "n1", "time_ms": 300, "lane": 0, "kind": "tap"},
            {"note_id": "n1", "time_ms": 500, "lane": 0, "kind": "tap"},
        ],
        [
            {"note_id": "n1", "time_ms": 600, "lane": 0, "kind": "tap"},
            {"note_id": "n2", "time_ms": 400, "lane": 0, "kind": "tap"},
        ],
        [
            {"note_id": "n1", "time_ms": 100, "lane": 0, "kind": "hold",
             "duration_ms": 0},
        ],
    ]
    for chart in bad_charts:
        with pytest.raises(rc.RhythmError) as exc:
            instance.load_chart(chart)
        assert exc.value.code == "RHYTHM_CHART_INVALID"


def test_perfect_tap_scores_and_raises_combo():
    instance = judge()
    out = instance.press(510, 0)
    assert out["judgement"] == "perfect"
    assert out["note_id"] == "n1"
    assert out["delta_ms"] == 10
    assert out["combo"] == 1
    assert instance.combo() == 1
    assert instance.results()["perfect"] == 1
    assert instance.judge("n1").status == "judged"


def test_great_tap_between_windows():
    instance = judge()
    out = instance.press(1060, 0)
    assert out["judgement"] == "great"
    assert out["note_id"] == "n2"
    assert out["delta_ms"] == 60
    assert instance.results()["great"] == 1
    assert instance.results()["perfect"] == 0


def test_press_outside_window_is_ignored():
    instance = judge()
    out = instance.press(380, 0)
    assert out["judgement"] == "none"
    assert out["note_id"] is None
    assert instance.results()["judged"] == 0
    assert instance.stats()["ignored"] == 1
    assert instance.judge("n1").status == "pending"


def test_tick_marks_overdue_note_miss_and_resets_combo():
    instance = judge()
    instance.press(500, 0)
    assert instance.combo() == 1
    missed = instance.tick(1200)
    assert missed == ("n2",)
    assert instance.results()["miss"] == 1
    assert instance.combo() == 0
    assert instance.judge("n2").judgement == "miss"


def test_repeated_press_scores_the_note_once():
    instance = judge()
    first = instance.press(500, 0)
    second = instance.press(505, 0)
    assert first["judgement"] == "perfect"
    assert second["judgement"] == "none"
    assert instance.results()["perfect"] == 1
    assert instance.results()["judged"] == 1
    assert instance.stats()["presses"] == 2


def test_hold_head_and_tail_are_both_scored():
    instance = judge()
    head = instance.press(1510, 1)
    assert head["judgement"] == "perfect"
    assert instance.judge("n3").status == "holding"
    tail = instance.release(2020, 1)
    assert tail["judgement"] == "perfect"
    assert tail["note_id"] == "n3"
    assert tail["delta_ms"] == 20
    assert tail["broken"] is False
    assert instance.combo() == 2
    assert instance.results()["perfect"] == 2
    assert instance.judge("n3").status == "judged"


def test_early_release_breaks_the_hold():
    instance = judge()
    instance.press(1510, 1)
    out = instance.release(1700, 1)
    assert out["judgement"] == "miss"
    assert out["broken"] is True
    assert out["delta_ms"] == -300
    assert instance.combo() == 0
    assert instance.results()["miss"] == 1
    assert instance.judge("n3").status == "judged"


def test_positive_calibration_shifts_input_time():
    instance = judge()
    out = instance.calibrate(25)
    assert out["offset_ms"] == 25
    graded = instance.press(525, 0)
    assert graded["judgement"] == "perfect"
    assert graded["delta_ms"] == 0
    assert instance.stats()["calibrations"] == 1


def test_pause_freezes_judgement_until_resume():
    instance = judge()
    instance.pause()
    assert instance.tick(9999) == ()
    assert instance.results()["miss"] == 0
    instance.resume()
    missed = instance.tick(9999)
    assert missed == ("n1", "n2", "n3", "n4")
    assert instance.results()["miss"] == 4


def test_accuracy_weights_perfect_and_great():
    instance = judge()
    instance.press(500, 0)
    instance.press(1060, 0)
    assert instance.accuracy() == 80.0
    assert instance.results()["judged"] == 2
    assert instance.max_combo() == 2


def test_snapshot_restore_roundtrip_keeps_judgement_state():
    instance = judge()
    instance.press(500, 0)
    state = instance.snapshot()
    detached = copy.deepcopy(state)
    state["states"].clear()

    clone = rc.RhythmChartJudge()
    clone.restore(detached)
    assert clone.judge("n1").status == "judged"
    assert clone.combo() == 1
    assert clone.results()["perfect"] == 1
    follow = clone.press(1000, 0)
    assert follow["judgement"] == "perfect"
    assert clone.combo() == 2


def test_concurrent_press_on_same_note_scores_once():
    instance = judge()
    scored = []
    ignored = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait(timeout=5)
        try:
            out = instance.press(500, 0)
        except Exception as exc:  # noqa: BLE001 - reported through errors
            ignored.append(repr(exc))
        else:
            if out["judgement"] == "none":
                ignored.append(out)
            else:
                scored.append(out)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(scored) == 1
    assert len(ignored) == 7
    assert scored[0]["judgement"] == "perfect"
    assert instance.results()["perfect"] == 1
    assert instance.combo() == 1


def test_release_without_holding_is_ignored():
    instance = judge()
    out = instance.release(600, 1)
    assert out["judgement"] == "none"
    assert out["note_id"] is None
    assert out["broken"] is False
    assert instance.results()["judged"] == 0
