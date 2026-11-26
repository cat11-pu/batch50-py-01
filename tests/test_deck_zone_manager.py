import copy
import threading

import pytest

import deck_zone_manager as dz

CARDS = [f"card-{index:02d}" for index in range(20)]


def manager(**kwargs):
    options = {"seed": 7, "hand_limit": 8}
    options.update(kwargs)
    return dz.DeckZoneManager(**options)


def loaded(**kwargs):
    deck = manager(**kwargs)
    deck.load_deck(list(CARDS))
    return deck


def test_load_deck_keeps_given_order_and_counts():
    deck = loaded()
    assert deck.cards_in("deck") == tuple(CARDS)
    assert deck.zone_of("card-00") == "deck"
    assert deck.stats()["loaded"] == 20
    assert deck.cards_in("hand") == ()
    assert deck.cards_in("discard") == ()


def test_load_rejects_duplicates_and_blank_ids():
    deck = manager()
    bad = [
        [],
        ["a", "a"],
        ["a", ""],
        ["a", 5],
    ]
    for cards in bad:
        with pytest.raises(dz.DeckError) as exc:
            deck.load_deck(cards)
        assert exc.value.code == "DECK_INVALID_LOAD"
    assert deck.cards_in("deck") == ()


def test_draw_takes_cards_from_the_top_in_order():
    deck = loaded()
    hand = deck.draw(3)
    assert hand == ("card-00", "card-01", "card-02")
    assert deck.cards_in("hand") == ("card-00", "card-01", "card-02")
    assert deck.deck_top(2) == ("card-03", "card-04")
    assert deck.cards_in("deck")[0] == "card-03"
    assert deck.stats()["drawn"] == 3


def test_draw_rejects_non_positive_count_without_moving_cards():
    deck = loaded()
    for count in (0, -1, 2.5):
        with pytest.raises(dz.DeckError) as exc:
            deck.draw(count)
        assert exc.value.code == "DECK_INVALID_REQUEST"
    assert deck.cards_in("hand") == ()
    assert len(deck.cards_in("deck")) == 20


def test_draw_respects_hand_limit():
    deck = loaded(hand_limit=2)
    assert deck.draw(2) == ("card-00", "card-01")
    with pytest.raises(dz.DeckError) as exc:
        deck.draw(1)
    assert exc.value.code == "DECK_HAND_LIMIT"
    assert deck.cards_in("hand") == ("card-00", "card-01")
    assert deck.cards_in("deck")[0] == "card-02"


def test_discard_moves_card_to_pile_in_order():
    deck = loaded()
    deck.draw(2)
    view = deck.discard("card-00")
    assert view.zone == "discard"
    assert view.index == 0
    assert deck.cards_in("discard") == ("card-00",)
    assert deck.cards_in("hand") == ("card-01",)
    second = deck.discard("card-01")
    assert second.index == 1
    assert deck.cards_in("discard") == ("card-00", "card-01")
    assert deck.stats()["discarded"] == 2


def test_discard_refuses_card_outside_hand():
    deck = loaded()
    with pytest.raises(dz.DeckError) as exc:
        deck.discard("card-05")
    assert exc.value.code == "DECK_NOT_IN_HAND"
    assert deck.zone_of("card-05") == "deck"
    assert deck.cards_in("discard") == ()


def test_exile_accepts_hand_or_deck_card():
    deck = loaded()
    deck.draw(2)
    from_hand = deck.exile("card-01")
    assert from_hand.zone == "exile"
    from_deck = deck.exile("card-09")
    assert from_deck.zone == "exile"
    assert deck.cards_in("exile") == ("card-01", "card-09")
    assert "card-09" not in deck.cards_in("deck")
    assert deck.stats()["exiled"] == 2


def test_deploy_moves_hand_card_to_battlefield():
    deck = loaded()
    deck.draw(3)
    view = deck.deploy("card-02")
    assert view.zone == "battlefield"
    assert deck.cards_in("battlefield") == ("card-02",)
    assert deck.cards_in("hand") == ("card-00", "card-01")
    assert deck.stats()["deployed"] == 1


def test_shuffle_is_deterministic_for_same_seed():
    first = loaded()
    second = loaded()
    report = first.shuffle()
    assert report["seq"] == 1
    assert report["count"] == 20
    second.shuffle()
    assert first.cards_in("deck") == second.cards_in("deck")
    assert first.cards_in("deck") != tuple(CARDS)
    assert sorted(first.cards_in("deck")) == sorted(CARDS)


def test_shuffle_advances_sequence_and_changes_order():
    deck = loaded()
    first = deck.shuffle()
    order_one = deck.cards_in("deck")
    second = deck.shuffle(reason="effect")
    order_two = deck.cards_in("deck")
    assert (first["seq"], second["seq"]) == (1, 2)
    assert order_one != order_two
    assert deck.stats()["shuffles"] == 2


def test_mulligan_returns_and_redraws_same_count():
    deck = loaded()
    deck.draw(7)
    before = deck.cards_in("hand")
    report = deck.mulligan(["card-00", "card-03"])
    assert report["returned"] == 2
    assert len(report["drawn"]) == 2
    assert len(deck.cards_in("hand")) == 7
    assert len(set(deck.cards_in("hand"))) == 7
    assert sorted(set(deck.cards_in("hand")) | set(deck.cards_in("deck"))) == sorted(CARDS)
    assert deck.stats()["mulligans"] == 1
    assert len(before) == 7


def test_describe_reports_zone_position_and_visibility():
    deck = loaded()
    deck.draw(2)
    hand_view = deck.describe("card-00")
    assert hand_view.zone == "hand"
    assert hand_view.index == 0
    assert hand_view.visible is True
    deck_view = deck.describe("card-05")
    assert deck_view.zone == "deck"
    assert deck_view.index == 3
    assert deck_view.visible is False


def test_concurrent_draws_conserve_every_card():
    deck = loaded(hand_limit=40)
    drawn = []
    errors = []
    barrier = threading.Barrier(12)

    def worker():
        barrier.wait(timeout=5)
        try:
            drawn.append(deck.draw(1)[0])
        except Exception as exc:  # noqa: BLE001 - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(drawn) == 12
    assert len(set(drawn)) == 12
    assert sorted(drawn) == sorted(CARDS[:12])
    assert len(deck.cards_in("deck")) == 8
    assert deck.stats()["drawn"] == 12


def test_snapshot_restore_roundtrip_keeps_zones_and_position():
    deck = loaded()
    deck.draw(4)
    deck.discard("card-01")
    deck.shuffle()
    state = deck.snapshot()
    detached = copy.deepcopy(state)
    state["zones"].clear()

    clone = manager()
    clone.restore(detached)
    assert clone.cards_in("deck") == deck.cards_in("deck")
    assert clone.cards_in("hand") == deck.cards_in("hand")
    assert clone.cards_in("discard") == ("card-01",)
    assert clone.describe("card-00").zone == "hand"
    assert clone.stats()["drawn"] == 4

    twin = manager()
    twin.restore(copy.deepcopy(detached))
    assert clone.draw(2) == twin.draw(2)
