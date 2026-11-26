import threading

import pytest

import rank_ladder_series as rl

NOW = 1_800_000_000
RANKS = ("bronze", "silver", "gold")


def ladder(**kwargs):
    kwargs.setdefault("ranks", RANKS)
    return rl.RankLadderSeries(**kwargs)


def test_register_player_creates_standing():
    instance = ladder(protection_charges=2)
    standing = instance.register_player("alice")
    assert standing["player_id"] == "alice"
    assert standing["rank"] == "bronze"
    assert standing["rank_index"] == 0
    assert standing["protection_charges"] == 2
    assert standing["promotions"] == 0
    assert standing["demotions"] == 0
    assert standing["matches_played"] == 0
    assert standing["series"] is None
    assert standing["history"] == ()
    assert {"player_id", "rank", "rank_index", "protection_charges",
            "promotions", "demotions", "matches_played", "series",
            "history"} <= set(standing)
    with pytest.raises(rl.RankError) as exc:
        instance.register_player("alice")
    assert exc.value.code == "RANK_DUPLICATE_PLAYER"
    with pytest.raises(rl.RankError) as exc:
        instance.register_player("bob", rank_index=9)
    assert exc.value.code == "RANK_INVALID_REQUEST"
    with pytest.raises(rl.RankError) as exc:
        rl.RankLadderSeries(ranks=("solo",))
    assert exc.value.code == "RANK_INVALID_CONFIG"
    with pytest.raises(rl.RankError) as exc:
        rl.RankLadderSeries(ranks=RANKS, wins_needed=0)
    assert exc.value.code == "RANK_INVALID_CONFIG"


def test_unknown_player_is_rejected():
    instance = ladder()
    calls = [
        lambda: instance.series_of("ghost"),
        lambda: instance.standings("ghost"),
        lambda: instance.report_match("ghost", match_id="m1", result="win"),
        lambda: instance.promote("ghost"),
        lambda: instance.demote("ghost"),
    ]
    for call in calls:
        with pytest.raises(rl.RankError) as exc:
            call()
        assert exc.value.code == "RANK_UNKNOWN_PLAYER"


def test_start_series_opens_promotion_window():
    instance = ladder()
    instance.register_player("alice")
    series = instance.start_series("alice", now=NOW)
    assert series.player_id == "alice"
    assert series.current_rank == "bronze"
    assert series.target_rank == "silver"
    assert series.wins == 0
    assert series.losses == 0
    assert series.matches_left == 4
    assert series.status == "active"
    assert series.started_at == NOW
    assert series.expires_at == NOW + 3600
    assert instance.series_of("alice") == series
    with pytest.raises(rl.RankError) as exc:
        instance.start_series("alice", now=NOW + 10)
    assert exc.value.code == "RANK_SERIES_ACTIVE"


def test_top_rank_cannot_start_series():
    instance = ladder()
    instance.register_player("top", rank_index=2)
    with pytest.raises(rl.RankError) as exc:
        instance.start_series("top", now=NOW)
    assert exc.value.code == "RANK_TOP_RANK"


def test_report_match_updates_series_counters():
    instance = ladder()
    instance.register_player("alice")
    instance.start_series("alice", now=NOW)
    first = instance.report_match("alice", match_id="m1", result="win",
                                  now=NOW + 10)
    assert first.wins == 1
    assert first.losses == 0
    assert first.matches_left == 3
    second = instance.report_match("alice", match_id="m2", result="loss",
                                   now=NOW + 20)
    assert second.wins == 1
    assert second.losses == 1
    assert second.matches_left == 2
    with pytest.raises(rl.RankError) as exc:
        instance.report_match("alice", match_id="m3", result="draw")
    assert exc.value.code == "RANK_INVALID_REQUEST"
    assert instance.series_of("alice").matches_left == 2
    assert instance.stats()["matches_reported"] == 2


def test_duplicate_match_report_is_ignored():
    instance = ladder()
    instance.register_player("alice")
    instance.start_series("alice", now=NOW)
    instance.report_match("alice", match_id="m1", result="win", now=NOW + 10)
    with pytest.raises(rl.RankError) as exc:
        instance.report_match("alice", match_id="m1", result="win",
                              now=NOW + 20)
    assert exc.value.code == "RANK_DUPLICATE_MATCH"
    series = instance.series_of("alice")
    assert series.wins == 1
    assert series.matches_left == 3
    assert instance.stats()["duplicates"] == 1


def test_report_without_series_is_refused():
    instance = ladder()
    instance.register_player("alice")
    with pytest.raises(rl.RankError) as exc:
        instance.report_match("alice", match_id="m1", result="win")
    assert exc.value.code == "RANK_NO_SERIES"
    with pytest.raises(rl.RankError) as exc:
        instance.expire_series("alice", now=NOW)
    assert exc.value.code == "RANK_NO_SERIES"


def test_won_series_can_be_promoted():
    instance = ladder()
    instance.register_player("alice")
    instance.start_series("alice", now=NOW)
    instance.report_match("alice", match_id="m1", result="win", now=NOW + 10)
    series = instance.report_match("alice", match_id="m2", result="win",
                                   now=NOW + 20)
    assert series.status == "won"
    assert series.matches_left == 2
    standing = instance.promote("alice", now=NOW + 30)
    assert standing["rank"] == "silver"
    assert standing["rank_index"] == 1
    assert standing["promotions"] == 1
    assert standing["series"] is None
    assert standing["history"][-1]["kind"] == "promoted"
    assert instance.series_of("alice") is None
    assert instance.stats()["promotions"] == 1


def test_lost_series_cannot_be_promoted():
    instance = ladder()
    instance.register_player("alice")
    instance.start_series("alice", now=NOW)
    instance.report_match("alice", match_id="m1", result="loss", now=NOW + 10)
    series = instance.report_match("alice", match_id="m2", result="loss",
                                   now=NOW + 20)
    assert series.status == "lost"
    assert series.matches_left == 2
    with pytest.raises(rl.RankError) as exc:
        instance.promote("alice", now=NOW + 30)
    assert exc.value.code == "RANK_NOT_ELIGIBLE"
    assert instance.standings("alice")["rank"] == "bronze"
    assert instance.series_of("alice").status == "lost"


def test_report_after_terminal_series_is_refused():
    instance = ladder()
    instance.register_player("alice")
    instance.start_series("alice", now=NOW)
    instance.report_match("alice", match_id="m1", result="win", now=NOW + 10)
    instance.report_match("alice", match_id="m2", result="win", now=NOW + 20)
    with pytest.raises(rl.RankError) as exc:
        instance.report_match("alice", match_id="m3", result="loss",
                              now=NOW + 30)
    assert exc.value.code == "RANK_SERIES_CLOSED"


def test_demote_at_bottom_rank_is_refused():
    instance = ladder(protection_charges=2)
    instance.register_player("alice")
    with pytest.raises(rl.RankError) as exc:
        instance.demote("alice", now=NOW)
    assert exc.value.code == "RANK_BOTTOM_RANK"
    standing = instance.standings("alice")
    assert standing["rank"] == "bronze"
    assert standing["demotions"] == 0


def test_standings_expose_series_and_expiry_window():
    instance = ladder()
    instance.register_player("alice")
    instance.start_series("alice", now=NOW)
    instance.report_match("alice", match_id="m1", result="win", now=NOW + 10)
    unchanged = instance.expire_series("alice", now=NOW + 10)
    assert unchanged.status == "active"
    assert unchanged.wins == 1
    assert unchanged.matches_left == 3
    standing = instance.standings("alice")
    assert standing["matches_played"] == 1
    assert {"target_rank", "wins", "losses", "matches_left",
            "status"} <= set(standing["series"])
    assert standing["series"]["wins"] == 1
    assert standing["series"]["status"] == "active"
    assert instance.stats()["expired"] == 0


def test_reset_season_clears_series_but_keeps_history():
    instance = ladder()
    instance.register_player("alice")
    instance.start_series("alice", now=NOW)
    instance.report_match("alice", match_id="m1", result="win", now=NOW + 10)
    instance.report_match("alice", match_id="m2", result="win", now=NOW + 20)
    cleared = instance.reset_season(now=NOW + 30)
    assert cleared == 1
    assert instance.series_of("alice") is None
    standing = instance.standings("alice")
    assert standing["rank"] == "bronze"
    assert standing["history"][0]["result"] == "won"
    assert instance.stats()["season_resets"] == 1


def test_snapshot_roundtrip_and_invalid_restore():
    instance = ladder(protection_charges=2)
    instance.register_player("alice")
    instance.start_series("alice", now=NOW)
    instance.report_match("alice", match_id="m1", result="win", now=NOW + 10)
    instance.report_match("alice", match_id="m2", result="loss", now=NOW + 20)
    snap = instance.snapshot()
    fresh = ladder(protection_charges=2)
    fresh.restore(snap)
    assert fresh.series_of("alice") == instance.series_of("alice")
    assert fresh.standings("alice") == instance.standings("alice")
    instance.register_player("bob")
    with pytest.raises(rl.RankError) as exc:
        fresh.standings("bob")
    assert exc.value.code == "RANK_UNKNOWN_PLAYER"
    before = fresh.series_of("alice")
    with pytest.raises(rl.RankError) as exc:
        fresh.restore({"players": []})
    assert exc.value.code == "RANK_SNAPSHOT_INVALID"
    assert fresh.series_of("alice") == before


def test_concurrent_duplicate_reports_count_once():
    instance = ladder()
    instance.register_player("alice")
    instance.start_series("alice", now=NOW)
    barrier = threading.Barrier(8)
    accepted = []
    rejected = []
    lock = threading.Lock()

    def worker():
        try:
            barrier.wait(timeout=5)
            record = instance.report_match("alice", match_id="m-1",
                                           result="win", now=NOW + 10)
            with lock:
                accepted.append(record)
        except rl.RankError as exc:
            with lock:
                rejected.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert len(accepted) == 1
    assert rejected == ["RANK_DUPLICATE_MATCH"] * 7
    assert instance.series_of("alice").wins == 1
    assert instance.stats()["duplicates"] == 7
