import copy
import threading

import pytest

import weiqi_rule_arbiter as wr

BLACK = "black"
WHITE = "white"


def arbiter(**kwargs):
    options = {"size": 5}
    options.update(kwargs)
    return wr.WeiqiRuleArbiter(**options)


def place(arb, color, coord):
    return arb.place_stone(color, coord)


def test_first_move_is_recorded_and_visible():
    arb = arbiter()
    record = place(arb, BLACK, (2, 2))
    assert record.move_no == 1
    assert record.color == BLACK
    assert record.kind == "stone"
    assert record.coord == (2, 2)
    assert record.captured == ()
    assert arb.stone_at((2, 2)) == BLACK
    assert arb.stones_of(BLACK) == ((2, 2),)
    assert len(arb.move_log()) == 1
    assert arb.stats()["moves"] == 1


def test_occupied_intersection_is_refused_before_turn_order():
    arb = arbiter()
    place(arb, BLACK, (2, 2))
    with pytest.raises(wr.WeiqiError) as exc:
        place(arb, WHITE, (2, 2))
    assert exc.value.code == "WEIQI_POINT_OCCUPIED"
    assert len(arb.move_log()) == 1
    assert arb.stats()["refused"] == 1


def test_suicide_without_capture_is_refused():
    arb = arbiter()
    place(arb, BLACK, (4, 4))
    place(arb, WHITE, (0, 1))
    place(arb, BLACK, (4, 3))
    place(arb, WHITE, (1, 0))
    with pytest.raises(wr.WeiqiError) as exc:
        place(arb, BLACK, (0, 0))
    assert exc.value.code == "WEIQI_SUICIDE"
    assert arb.stone_at((0, 0)) is None
    assert arb.stats()["moves"] == 4


def test_capture_removes_libertyless_stone_and_counts():
    arb = arbiter()
    place(arb, BLACK, (0, 1))
    place(arb, WHITE, (4, 4))
    record = place(arb, BLACK, (1, 0))
    assert record.captured == ((0, 0),)
    assert arb.stone_at((0, 0)) is None
    assert arb.captures_of(BLACK) == 1
    assert arb.captures_of(WHITE) == 0
    assert arb.stats()["captures"] == {"black": 1, "white": 0}


def test_turn_order_must_alternate():
    arb = arbiter()
    place(arb, BLACK, (2, 2))
    with pytest.raises(wr.WeiqiError) as exc:
        place(arb, BLACK, (2, 3))
    assert exc.value.code == "WEIQI_TURN_ORDER"
    place(arb, WHITE, (2, 3))
    assert len(arb.move_log()) == 2


def test_immediate_ko_recapture_is_refused():
    arb = arbiter()
    sequence = [
        (BLACK, (2, 1)),
        (WHITE, (2, 2)),
        (BLACK, (0, 1)),
        (WHITE, (0, 2)),
        (BLACK, (1, 0)),
        (WHITE, (1, 3)),
        (BLACK, (3, 0)),
        (WHITE, (1, 1)),
    ]
    for color, coord in sequence:
        place(arb, color, coord)
    capture = place(arb, BLACK, (1, 2))
    assert capture.captured == ((1, 1),)
    before = arb.position_hash()
    with pytest.raises(wr.WeiqiError) as exc:
        place(arb, WHITE, (1, 1))
    assert exc.value.code == "WEIQI_KO"
    assert arb.position_hash() == before


def test_two_passes_end_the_game_and_block_further_moves():
    arb = arbiter()
    place(arb, BLACK, (0, 0))
    place(arb, WHITE, (4, 4))
    first = arb.pass_turn(BLACK)
    assert first.kind == "pass"
    assert first.coord is None
    second = arb.pass_turn(WHITE)
    assert second.move_no == 4
    assert arb.stats()["passes"] == 2
    with pytest.raises(wr.WeiqiError) as exc:
        place(arb, BLACK, (2, 2))
    assert exc.value.code == "WEIQI_GAME_OVER"


def test_area_score_counts_stones_and_ignores_neutral_points():
    arb = arbiter()
    place(arb, BLACK, (0, 0))
    place(arb, WHITE, (4, 4))
    board = arb.score()
    assert board["black"] == {"stones": 1, "territory": 0, "total": 1}
    assert board["white"] == {"stones": 1, "territory": 0, "total": 7.5}
    assert board["komi"] == 6.5
    assert board["winner"] == WHITE


def test_resign_ends_the_game_with_a_result():
    arb = arbiter()
    place(arb, BLACK, (2, 2))
    outcome = arb.resign(WHITE)
    assert outcome["winner"] == BLACK
    assert outcome["reason"] == "resign"
    assert outcome["moves"] == 1
    with pytest.raises(wr.WeiqiError) as exc:
        place(arb, WHITE, (2, 3))
    assert exc.value.code == "WEIQI_GAME_OVER"


def test_main_time_is_charged_per_side():
    arb = arbiter(main_time=300)
    place(arb, BLACK, (0, 0))
    after = arb.tick_clock(BLACK, 100)
    assert after["main_left"] == 200
    assert after["in_byo_yomi"] is False
    white = arb.clock_state(WHITE)
    assert white["main_left"] == 300
    assert white["in_byo_yomi"] is False
    assert arb.clock_state(BLACK)["main_left"] == 200


def test_byo_yomi_period_is_lost_only_when_fully_overrun():
    arb = arbiter(main_time=300, byo_yomi=30, byo_yomi_periods=3)
    state = arb.tick_clock(BLACK, 312)
    assert state["main_left"] == 0
    assert state["in_byo_yomi"] is True
    assert state["periods_left"] == 3
    assert state["period_left"] == 18
    overrun = arb.tick_clock(BLACK, 40)
    assert overrun["main_left"] == 0
    assert overrun["periods_left"] == 2
    assert overrun["period_left"] == 30
    assert overrun["in_byo_yomi"] is True


def test_pause_freezes_only_the_requested_clock():
    arb = arbiter(main_time=300)
    paused = arb.pause_clock(BLACK)
    assert paused["paused"] is True
    still = arb.tick_clock(BLACK, 50)
    assert still["main_left"] == 300
    other = arb.tick_clock(WHITE, 50)
    assert other["main_left"] == 250
    resumed = arb.resume_clock(BLACK)
    assert resumed["paused"] is False
    charged = arb.tick_clock(BLACK, 50)
    assert charged["main_left"] == 250


def test_undo_latest_move_restores_position_and_turn():
    arb = arbiter()
    place(arb, BLACK, (2, 2))
    place(arb, WHITE, (0, 1))
    place(arb, BLACK, (1, 0))
    undo = arb.undo_request(WHITE)
    assert undo["undone"] == 2
    assert undo["color"] == WHITE
    assert undo["coord"] == (0, 1)
    assert arb.stone_at((0, 1)) is None
    assert arb.stone_at((1, 0)) == BLACK
    assert len(arb.move_log()) == 1
    place(arb, WHITE, (0, 2))
    assert arb.stone_at((0, 2)) == WHITE
    assert arb.stats()["undos"] == 1


def test_concurrent_placements_on_distinct_points_accept_one_move():
    arb = arbiter()
    points = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)]
    accepted = []
    refused = []
    barrier = threading.Barrier(len(points))

    def worker(coord):
        barrier.wait(timeout=5)
        try:
            record = arb.place_stone(BLACK, coord)
        except Exception as exc:  # noqa: BLE001 - refusals are expected
            refused.append(exc)
        else:
            accepted.append(record)

    threads = [threading.Thread(target=worker, args=(point,)) for point in points]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(accepted) == 1
    assert len(refused) == len(points) - 1
    assert {getattr(exc, "code", None) for exc in refused} == {"WEIQI_TURN_ORDER"}
    assert len(arb.move_log()) == 1
    assert arb.stats()["moves"] == 1


def test_snapshot_roundtrip_keeps_position_and_clocks():
    arb = arbiter(main_time=300)
    place(arb, BLACK, (2, 2))
    place(arb, WHITE, (2, 3))
    arb.tick_clock(BLACK, 60)
    state = arb.snapshot()
    detached = copy.deepcopy(state)
    state["moves"].clear()

    clone = arbiter(main_time=300)
    clone.restore(detached)
    assert clone.stone_at((2, 2)) == BLACK
    assert clone.stone_at((2, 3)) == WHITE
    assert len(clone.move_log()) == 2
    assert clone.clock_state(BLACK)["main_left"] == 240
    assert clone.stats()["moves"] == 2
    place(clone, BLACK, (3, 3))
    assert clone.stone_at((3, 3)) == BLACK
    assert clone.stats()["moves"] == 3
