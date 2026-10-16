"""The end of the view that holds a hit is looked up, not searched for, on the raw text too.

A quoted gap or a framing quote has to close inside the view the hit is in, so each hit asks
where that view ends. On a view of the input the alignment answers from the separators it
found once. On the raw text itself there is no alignment, and the answer used to be a search
to the end of the text for every hit, so work grew with the square of the number of hits now
that the count cap is gone. The running scan finds the separators of the raw text once.
"""
import pytest

from sunglasses import engine as engine_module
from sunglasses.engine import SunglassesEngine

BLOCKING = ("block", "quarantine")
QUOTED_NEGATION = 'Never use "zorbit now" here. '
QUOTED_FRAMING = 'Our scanner detects examples "zorbit now". '
BARE = "Now zorbit now happens. "


def _rule(rule_id):
    return {
        "id": rule_id, "name": rule_id, "category": "test", "severity": "high",
        "channel": ["message"], "keywords": [], "description": "test rule",
        "regex": [r"(?i)zorbit now"],
    }


def _count_searches(monkeypatch):
    calls = {"static": 0}
    real = engine_module._RawAlign.view_end

    def counted(view, pos):
        calls["static"] += 1
        return real(view, pos)

    monkeypatch.setattr(engine_module._RawAlign, "view_end", staticmethod(counted))
    return calls


@pytest.mark.parametrize("unit,rule_id,marker", [
    (QUOTED_NEGATION, "GLS-TEST-001", "negation_context"),
    (QUOTED_FRAMING, "GLS-MECH-TEST-001", "defensive_context"),
])
@pytest.mark.parametrize("copies", [50, 400, 1600])
def test_many_quoted_hits_on_the_raw_text_search_for_no_view_end(monkeypatch, unit, rule_id, marker, copies):
    calls = _count_searches(monkeypatch)
    eng = SunglassesEngine(patterns=[_rule(rule_id)], mechanisms=False)
    result = eng.scan(unit * copies, "message")
    found = [f for f in result.findings if f["id"] == rule_id]
    assert result.decision == "allow_redacted"
    assert found and found[0]["severity"] == "review" and found[0].get(marker) is True
    assert calls["static"] == 0, calls


@pytest.mark.parametrize("unit,rule_id", [
    (QUOTED_NEGATION, "GLS-TEST-001"),
    (QUOTED_FRAMING, "GLS-MECH-TEST-001"),
])
def test_a_bare_hit_after_many_quoted_ones_is_still_live(monkeypatch, unit, rule_id):
    calls = _count_searches(monkeypatch)
    eng = SunglassesEngine(patterns=[_rule(rule_id)], mechanisms=False)
    result = eng.scan(unit * 800 + BARE, "message")
    assert result.decision in BLOCKING
    assert calls["static"] == 0, calls


def test_the_raw_text_view_end_matches_the_search_it_replaces():
    sep = " " + engine_module.VIEW_SEP + " "
    text = "aa" + sep + "bbbb" + sep + "cc" + sep + "d"
    ends = engine_module._ViewEnds()
    for pos in range(len(text) + 1):
        assert ends.end_of_view(text, pos) == engine_module._RawAlign.view_end(text, pos), pos


def test_a_view_end_asked_outside_a_scan_still_answers():
    sep = " " + engine_module.VIEW_SEP + " "
    text = "aa" + sep + "bb"
    assert SunglassesEngine._view_end(text, 0) == 2
    assert SunglassesEngine._view_end(text, 3) == len(text)


def test_the_scan_local_index_is_restored_when_a_scan_raises():
    eng = SunglassesEngine(patterns=[_rule("GLS-TEST-001")], mechanisms=False)
    before = getattr(engine_module._SCAN_LOCAL, "ends", None)
    with pytest.raises(ValueError):
        eng.scan("x", "no-such-channel")
    assert getattr(engine_module._SCAN_LOCAL, "ends", None) is before
    eng.scan("x", "message")
    assert getattr(engine_module._SCAN_LOCAL, "ends", None) is before


# A quote that closes far away is searched for once for the walk, not once per hit.
def _count_close_work(monkeypatch):
    work = {"searches": 0, "chars": 0}
    real = SunglassesEngine._scan_close

    def counted(text, close, start, stop):
        found = real(text, close, start, stop)
        work["searches"] += 1
        work["chars"] += (stop if found == -1 else found) - start
        return found

    monkeypatch.setattr(SunglassesEngine, "_scan_close", staticmethod(counted))
    return work


@pytest.mark.parametrize("unit,rule_id,marker", [
    ('Never use “zorbit now here. ', "GLS-TEST-001", "negation_context"),
    ('Our scanner detects examples “zorbit now. ', "GLS-MECH-TEST-001", "defensive_context"),
])
@pytest.mark.parametrize("copies", [400, 1600, 6400])
def test_a_quote_that_closes_far_away_is_searched_for_once(monkeypatch, unit, rule_id, marker, copies):
    work = _count_close_work(monkeypatch)
    eng = SunglassesEngine(patterns=[_rule(rule_id)], mechanisms=False)
    text = unit * copies + "”"
    result = eng.scan(text, "message")
    found = [f for f in result.findings if f["id"] == rule_id]
    assert result.decision == "allow_redacted" and found and found[0].get(marker) is True
    assert work["chars"] <= 8 * len(text), work


@pytest.mark.parametrize("close", ["\"", "'", "```", "”", "»"])
def test_the_kept_closing_mark_answers_as_a_fresh_search_does(close):
    import random
    rng = random.Random(7)
    pieces = [close, "a", "b", " ", "'", "x'y", close[:1], "\n"]
    ends = engine_module._ViewEnds()
    for _ in range(200):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 40)))
        for _ in range(60):
            start = rng.randint(0, len(text))
            stop = rng.randint(start, len(text))
            want = SunglassesEngine._scan_close(text, close, start, stop)
            got = ends.first_close(text, close, start, stop, SunglassesEngine._scan_close)
            assert got == want, (text, close, start, stop, got, want)


@pytest.mark.parametrize("close", ["\"", "'", "```"])
def test_the_kept_closing_mark_follows_a_walk_of_rising_starts(close):
    import random
    rng = random.Random(11)
    pieces = [close, "a", " ", "'", "q'r", "z"]
    for _ in range(150):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 60)))
        ends = engine_module._ViewEnds()
        start = 0
        while start <= len(text):
            stop = rng.randint(start, len(text))
            assert ends.first_close(text, close, start, stop, SunglassesEngine._scan_close) == \
                SunglassesEngine._scan_close(text, close, start, stop), (text, close, start, stop)
            start += rng.randint(0, 5)
