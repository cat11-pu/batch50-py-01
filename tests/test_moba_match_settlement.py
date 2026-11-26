import copy
import threading

import pytest

import moba_match_settlement as ms

BLUE = "blue"
RED = "red"


def settlement(**kwargs):
    return ms.MobaMatchSettlement(**kwargs)


def line(player_id, team, *, kills=0, deaths=0, assists=0, dealt=0, taken=0,
         vision=0, active=1.0):
    return ms.PlayerLine(player_id, team, kills, deaths, assists, dealt, taken,
                         vision, active)


def report(svc, match_id, players, *, winner=BLUE, duration=1800, mode="normal"):
    return svc.report_match(match_id, duration=duration, players=players,
                            winner=winner, mode=mode)


def standard_players():
    return [
        line("b-ruo", BLUE, kills=5, deaths=1, assists=3, dealt=12000,
             taken=8000, vision=20),
        line("b-lin", BLUE, kills=2, deaths=3, assists=4, dealt=9000,
             taken=11000, vision=10, active=0.9),
        line("r-kai", RED, kills=1, deaths=4, assists=2, dealt=7000,
             taken=9000, vision=5),
        line("r-mo", RED, kills=0, deaths=6, assists=1, dealt=4000,
             taken=10000, vision=3, active=0.8),
    ]


def test_report_settles_team_ratings_and_streak_start():
    svc = settlement()
    out = report(svc, "m-1", standard_players())
    assert out.match_id == "m-1"
    assert out.mode == "normal"
    assert out.winner == BLUE
    assert out.duration == 1800
    assert out.scores == {"b-ruo": 38, "b-lin": 25, "r-kai": 12, "r-mo": 0}
    assert out.rating_delta == {"b-ruo": 55, "b-lin": 25, "r-kai": -12, "r-mo": -12}
    assert out.streak_bonus == {"b-ruo": 5, "b-lin": 5, "r-kai": 0, "r-mo": 0}

    assert svc.player_summary("b-ruo") == ms.PlayerSummary(
        "b-ruo", 55, 1, 1, 0, 1, 1, 1
    )
    assert svc.player_summary("r-kai") == ms.PlayerSummary(
        "r-kai", -12, 1, 0, 1, 0, 0, 0
    )
    assert svc.stats()["matches"] == 1


def test_mvp_comes_from_winning_team_and_gets_bonus():
    svc = settlement()
    players = [
        line("b-one", BLUE, kills=1, deaths=2, assists=1, dealt=1000,
             taken=1000),
        line("b-two", BLUE, kills=0, deaths=1, assists=2, dealt=3000,
             vision=10, active=0.9),
        line("r-star", RED, kills=8, deaths=1, assists=5, dealt=20000,
             taken=15000, vision=30),
        line("r-two", RED, kills=0, deaths=5, assists=1, dealt=2000,
             taken=12000, vision=5),
    ]
    out = report(svc, "m-2", players)
    assert out.scores["r-star"] == 65
    assert out.scores["b-two"] == 6
    assert out.scores["b-one"] == 2
    assert out.mvp == "b-two"
    assert svc.mvp_of("m-2") == "b-two"
    assert out.rating_delta["b-two"] == 55
    assert out.rating_delta["r-star"] == -12
    assert svc.player_summary("b-two").mvp_count == 1


def test_mvp_score_weights_kills_deaths_assists():
    svc = settlement()
    score = svc.mvp_score(line("x", BLUE, kills=7, deaths=1, assists=9,
                               dealt=23450, taken=31200, vision=87))
    assert score == 88


def test_mvp_score_includes_damage_and_vision():
    svc = settlement()
    assert svc.mvp_score(line("a", BLUE, dealt=5000, taken=3000, vision=40)) == 11
    assert svc.mvp_score(line("b", BLUE, kills=3)) == 9
    assert svc.mvp_score(line("c", BLUE, deaths=1, assists=1)) == 0


def test_mvp_tie_broken_by_deaths_then_player_id():
    svc = settlement()
    players = [
        line("b-alpha", BLUE, kills=1, assists=1),
        line("a-beta", BLUE, kills=1, assists=1),
        line("c-gamma", BLUE, kills=1, deaths=2, assists=3),
        line("r-one", RED),
        line("r-two", RED),
    ]
    out = report(svc, "m-tie", players)
    assert out.scores["b-alpha"] == 5
    assert out.scores["a-beta"] == 5
    assert out.scores["c-gamma"] == 5
    assert out.mvp == "a-beta"


def test_streak_bonus_accumulates_and_caps():
    svc = settlement(win_points=10, mvp_bonus=0, streak_step=5, streak_cap=3)
    winner = line("p1", BLUE, kills=2, assists=1)
    loser = line("r1", RED)
    bonuses = []
    for index in range(1, 5):
        out = report(svc, f"s-{index}", [winner, loser])
        bonuses.append(out.streak_bonus["p1"])
    assert bonuses == [5, 10, 15, 15]
    summary = svc.player_summary("p1")
    assert summary.rating == 85
    assert summary.streak == 4
    assert summary.best_streak == 4
    assert summary.wins == 4
    assert summary.matches == 4
    assert svc.streak_bonus("p1") == 15


def test_loss_resets_streak_but_keeps_best():
    svc = settlement(mvp_bonus=0)
    winner = line("p1", BLUE, kills=2, assists=1)
    loser = line("r1", RED)
    report(svc, "w-1", [winner, loser])
    report(svc, "w-2", [winner, loser])
    assert svc.player_summary("p1").rating == 55
    report(svc, "w-3", [winner, loser], winner=RED)

    summary = svc.player_summary("p1")
    assert summary.rating == 43
    assert summary.streak == 0
    assert summary.best_streak == 2
    assert summary.wins == 2
    assert summary.losses == 1
    assert summary.matches == 3
    assert svc.streak_bonus("p1") == 0

    rival = svc.player_summary("r1")
    assert rival.rating == 1
    assert rival.streak == 1
    assert rival.wins == 1
    assert rival.losses == 2


def test_afk_player_is_flagged_and_excluded_from_rating():
    svc = settlement()
    players = [
        line("b-carry", BLUE, kills=3, deaths=1, assists=2, dealt=9000,
             taken=8000, vision=15),
        line("b-afk", BLUE, kills=12, deaths=0, assists=8, dealt=30000,
             taken=2000, vision=40, active=0.1),
        line("r-one", RED, kills=2, deaths=4, assists=1, dealt=7000,
             taken=9000, vision=8),
        line("r-two", RED, kills=1, deaths=3, assists=2, dealt=6000,
             taken=8000, vision=6),
    ]
    out = report(svc, "m-afk", players)
    assert out.afk == ("b-afk",)
    assert svc.afk_players("m-afk") == ("b-afk",)
    assert out.rating_delta["b-afk"] == 0
    assert svc.player_summary("b-afk") == ms.PlayerSummary(
        "b-afk", 0, 0, 0, 0, 0, 0, 0
    )


def test_report_rejects_malformed_player_lines():
    svc = settlement()
    good = [line("b1", BLUE), line("r1", RED)]
    cases = [
        ("", dict(duration=1800, players=good, winner=BLUE)),
        ("bad-duration", dict(duration=0, players=good, winner=BLUE)),
        ("bad-duplicate", dict(duration=1800,
                               players=[line("b1", BLUE), line("b1", RED)],
                               winner=BLUE)),
        ("bad-team", dict(duration=1800,
                          players=[line("b1", "green"), line("r1", RED)],
                          winner=BLUE)),
        ("bad-kills", dict(duration=1800,
                           players=[line("b1", BLUE, kills=-1), line("r1", RED)],
                           winner=BLUE)),
        ("bad-active", dict(duration=1800,
                            players=[line("b1", BLUE, active=1.5), line("r1", RED)],
                            winner=BLUE)),
        ("bad-type", dict(duration=1800,
                          players=[{"player_id": "b1"}, line("r1", RED)],
                          winner=BLUE)),
        ("bad-winner", dict(duration=1800, players=good, winner="green")),
        ("bad-mode", dict(duration=1800, players=good, winner=BLUE,
                          mode="tournament")),
        ("too-many", dict(duration=1800, winner=BLUE, players=[
            line(f"b{index}", BLUE) for index in range(6)
        ] + [line(f"r{index}", RED) for index in range(5)])),
    ]
    for match_id, kwargs in cases:
        with pytest.raises(ms.MobaError) as exc:
            svc.report_match(match_id, **kwargs)
        assert exc.value.code == "MATCH_INVALID_REQUEST"

    assert svc.stats()["matches"] == 0
    assert svc.leaderboard() == ()


def test_report_requires_both_teams():
    svc = settlement()
    with pytest.raises(ms.MobaError) as exc:
        report(svc, "m-one-side", [line("b1", BLUE), line("b2", BLUE)])
    assert exc.value.code == "MATCH_INVALID_REQUEST"

    with pytest.raises(ms.MobaError) as exc:
        report(svc, "m-empty", [])
    assert exc.value.code == "MATCH_INVALID_REQUEST"

    assert svc.stats()["players"] == 0
    assert svc.stats()["matches"] == 0


def test_unknown_match_and_player_queries_are_refused():
    svc = settlement()
    calls = [
        lambda: svc.settlement("nope"),
        lambda: svc.mvp_of("nope"),
        lambda: svc.afk_players("nope"),
        lambda: svc.player_summary("ghost"),
        lambda: svc.streak_bonus("ghost"),
    ]
    for call in calls:
        with pytest.raises(ms.MobaError) as exc:
            call()
        assert exc.value.code == "MATCH_UNKNOWN"


def test_leaderboard_sorted_by_rating_desc_then_id():
    svc = settlement()
    report(svc, "m-1", standard_players())
    second = [
        line("b-ruo", BLUE, kills=0, deaths=4, assists=1, dealt=3000,
             taken=9000, vision=4),
        line("b-lin", BLUE, kills=1, deaths=5, assists=0, dealt=4000,
             taken=10000, vision=2),
        line("r-kai", RED, kills=6, deaths=2, assists=3, dealt=16000,
             taken=12000, vision=22),
        line("r-mo", RED, kills=2, deaths=3, assists=2, dealt=8000,
             taken=9000, vision=9),
    ]
    report(svc, "m-2", second, winner=RED)

    assert [row.player_id for row in svc.leaderboard()] == [
        "b-ruo", "r-kai", "b-lin", "r-mo"
    ]
    assert [row.rating for row in svc.leaderboard()] == [43, 43, 13, 13]
    assert [row.player_id for row in svc.leaderboard(limit=2)] == ["b-ruo", "r-kai"]

    with pytest.raises(ms.MobaError) as exc:
        svc.leaderboard(limit=0)
    assert exc.value.code == "MATCH_INVALID_REQUEST"


def test_concurrent_reports_keep_match_count():
    svc = settlement()
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            players = [
                line(f"p{index}-1", BLUE, kills=3, assists=1),
                line(f"p{index}-2", BLUE),
                line(f"p{index}-3", RED, kills=2),
                line(f"p{index}-4", RED),
            ]
            report(svc, f"m-{index}", players)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert svc.stats()["matches"] == 8
    assert svc.stats()["players"] == 32
    assert len(svc.leaderboard(limit=32)) == 32


def test_snapshot_is_detached_and_restore_resumes_progress():
    svc = settlement()
    report(svc, "m-1", standard_players())
    second = [
        line("b-ruo", BLUE, kills=0, deaths=4, assists=1, dealt=3000,
             taken=9000, vision=4),
        line("b-lin", BLUE, kills=1, deaths=5, assists=0, dealt=4000,
             taken=10000, vision=2),
        line("r-kai", RED, kills=6, deaths=2, assists=3, dealt=16000,
             taken=12000, vision=22),
        line("r-mo", RED, kills=2, deaths=3, assists=2, dealt=8000,
             taken=9000, vision=9),
    ]
    report(svc, "m-2", second, winner=RED)

    state = svc.snapshot()
    assert set(state) == {"version", "players", "matches", "counters", "stats"}
    pristine = copy.deepcopy(state)

    state["players"].clear()
    state["matches"].clear()
    assert svc.player_summary("b-ruo").rating == 43
    assert svc.stats()["matches"] == 2

    clone = settlement()
    clone.restore(pristine)
    for player_id in ("b-ruo", "b-lin", "r-kai", "r-mo"):
        assert clone.player_summary(player_id) == svc.player_summary(player_id)
    assert clone.leaderboard() == svc.leaderboard()
    assert clone.settlement("m-1") == svc.settlement("m-1")
    assert clone.stats() == svc.stats()

    third = [
        line("b-ruo", BLUE, kills=7, deaths=1, assists=4, dealt=18000,
             taken=7000, vision=25),
        line("b-lin", BLUE, kills=1, deaths=2, assists=3, dealt=5000,
             taken=10000, vision=8),
        line("r-kai", RED, kills=2, deaths=5, assists=1, dealt=9000,
             taken=11000, vision=6),
        line("r-mo", RED, kills=0, deaths=4, assists=0, dealt=2000,
             taken=8000, vision=3),
    ]
    left = report(svc, "m-3", third)
    right = report(clone, "m-3", third)
    assert left == right
    assert clone.player_summary("b-ruo") == svc.player_summary("b-ruo")


def test_restore_rejects_malformed_state_without_mutation():
    svc = settlement()
    report(svc, "m-1", standard_players())
    before_summary = svc.player_summary("b-ruo")
    before_board = svc.leaderboard()
    before_stats = svc.stats()

    bad_states = [
        None,
        {},
        {"version": 2},
        {"version": 1, "players": []},
        {"version": 1, "players": {}, "matches": {}, "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(ms.MobaError) as exc:
            svc.restore(bad)
        assert exc.value.code == "MATCH_SNAPSHOT_INVALID"

    assert svc.player_summary("b-ruo") == before_summary
    assert svc.leaderboard() == before_board
    assert svc.stats() == before_stats
    assert svc.settlement("m-1").mvp == "b-ruo"
