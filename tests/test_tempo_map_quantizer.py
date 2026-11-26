import pytest

import tempo_map_quantizer as tq


def mapper(**kwargs):
    kwargs.setdefault("ppq", 480)
    kwargs.setdefault("sample_rate", 48000)
    kwargs.setdefault("max_anchors", 8)
    return tq.TempoMapQuantizer(**kwargs)


def test_default_map_starts_at_120_and_four_four():
    instance = mapper()
    anchors = instance.anchors()
    assert len(anchors) == 1
    assert anchors[0].tick == 0
    assert anchors[0].bpm == 120.0
    meter = instance.meter_at(0)
    assert meter.numerator == 4
    assert meter.denominator == 4
    assert instance.bar_line(0) == 0
    assert instance.stats()["tempos"] == 1


def test_add_tempo_records_anchor():
    instance = mapper()
    anchor = instance.add_tempo(960, 90.0)
    assert anchor.tick == 960
    assert anchor.bpm == 90.0
    assert [item.tick for item in instance.anchors()] == [0, 960]


def test_add_tempo_rejects_non_positive_bpm():
    instance = mapper()
    for bpm in (0.0, -60.0):
        with pytest.raises(tq.TempoMapError) as exc:
            instance.add_tempo(480, bpm)
        assert exc.value.code == "TEMPO_INVALID_BPM"
    assert len(instance.anchors()) == 1


def test_add_tempo_replaces_same_tick():
    instance = mapper()
    instance.add_tempo(0, 90.0)
    anchors = instance.anchors()
    assert len(anchors) == 1
    assert anchors[0].bpm == 90.0


def test_anchor_limit_is_hard():
    instance = mapper(max_anchors=2)
    instance.add_tempo(960, 90.0)
    with pytest.raises(tq.TempoMapError) as exc:
        instance.add_tempo(1920, 100.0)
    assert exc.value.code == "TEMPO_ANCHOR_LIMIT"
    assert len(instance.anchors()) == 2


def test_add_meter_requires_bar_line():
    instance = mapper()
    instance.add_meter(0, 4, 4)
    with pytest.raises(tq.TempoMapError) as exc:
        instance.add_meter(1000, 3, 4)
    assert exc.value.code == "TEMPO_INVALID_METER_POSITION"
    instance.add_meter(7680, 3, 4)
    assert instance.meter_at(9600).numerator == 3
    assert instance.meter_at(9600).denominator == 4


def test_add_meter_validates_signature():
    instance = mapper()
    for numerator, denominator in ((0, 4), (4, 5), (17, 4)):
        with pytest.raises(tq.TempoMapError) as exc:
            instance.add_meter(0, numerator, denominator)
        assert exc.value.code == "TEMPO_INVALID_METER"


def test_tick_to_sample_uses_segment_tempo():
    instance = mapper()
    assert instance.tick_to_sample(480) == 24000
    instance.add_tempo(480, 60.0)
    assert instance.tick_to_sample(480) == 24000
    assert instance.tick_to_sample(960) == 72000


def test_sample_to_tick_inverts():
    instance = mapper()
    assert instance.sample_to_tick(24000) == 480
    assert instance.sample_to_tick(36000) == 720
    with pytest.raises(tq.TempoMapError) as exc:
        instance.sample_to_tick(-1)
    assert exc.value.code == "TEMPO_INVALID_REQUEST"


def test_quantize_snaps_to_nearest_grid():
    instance = mapper()
    assert instance.quantize(130) == 120
    assert instance.quantize(190) == 240
    assert instance.quantize(60) == 0


def test_quantize_triplet_grid():
    instance = mapper()
    assert instance.quantize(70, triplet=True) == 80
    assert instance.quantize(30, triplet=True) == 0


def test_grid_at_returns_grid_ticks():
    instance = mapper()
    assert instance.grid_at(0, "1/4") == 480
    assert instance.grid_at(0, "1/16") == 120
    assert instance.grid_at(0, "1/16", triplet=True) == 80


def test_quantize_rejects_unknown_grid():
    instance = mapper()
    with pytest.raises(tq.TempoMapError) as exc:
        instance.grid_at(0, "1/7")
    assert exc.value.code == "TEMPO_GRID_UNSUPPORTED"
    with pytest.raises(tq.TempoMapError) as exc:
        instance.quantize(120, grid="3/8")
    assert exc.value.code == "TEMPO_GRID_UNSUPPORTED"


def test_remove_tempo_anchor():
    instance = mapper()
    instance.add_tempo(960, 90.0)
    removed = instance.remove_tempo(960)
    assert removed.tick == 960
    assert removed.bpm == 90.0
    assert len(instance.anchors()) == 1
    with pytest.raises(tq.TempoMapError) as exc:
        instance.remove_tempo(480)
    assert exc.value.code == "TEMPO_UNKNOWN_ANCHOR"
    with pytest.raises(tq.TempoMapError) as exc:
        instance.remove_tempo(0)
    assert exc.value.code == "TEMPO_INVALID_REQUEST"


def test_snapshot_restore_round_trip():
    instance = mapper()
    instance.add_tempo(480, 60.0)
    instance.add_meter(7680, 3, 4)
    instance.quantize(130)
    state = instance.snapshot()
    other = mapper()
    other.restore(state)
    assert [item.tick for item in other.anchors()] == [0, 480]
    assert other.meter_at(7680).numerator == 3
    assert other.tick_to_sample(960) == 72000
    assert other.stats()["tempos"] == 2
    assert other.stats()["meters"] == 2
    assert other.stats()["quantized"] == 1
