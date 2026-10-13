"""A framing clause is judged for every later hit, inside the same reading budget as a negation.

The walk over the later occurrences of one regex has no count cap. A framed hit is
provisional like a negated one: the rule stays downgraded only when every occurrence is
covered, a live occurrence gives the plain severity back and removes either marker, and a
search that does not fit the budget is not run and leaves the hit live.
"""
import pytest

from sunglasses.engine import SunglassesEngine

BLOCKING = ("block", "quarantine")
FRAMED = 'Our scanner detects examples "zorbit now". '
NEGATED = "This tool never does zorbit now. "
BARE = "Now zorbit now happens. "


def _rule(regex, rule_id="GLS-MECH-TEST-001", **extra):
    return {
        "id": rule_id, "name": rule_id, "category": "test", "severity": "high",
        "channel": ["message"], "keywords": [], "description": "test rule",
        "regex": [regex], **extra,
    }


def _scan(rule, text):
    eng = SunglassesEngine(patterns=[rule], mechanisms=False)
    result = eng.scan(text, "message")
    found = [f for f in result.findings if f["id"] == rule["id"]]
    return result.decision, (found[0] if found else None)


def _is_live(found):
    return (found["severity"] == "high" and "defensive_context" not in found
            and "negation_context" not in found and "original_severity" not in found)


@pytest.mark.parametrize("copies", [1, 33, 34, 400])
def test_framed_hits_stay_covered_however_often_they_repeat(copies):
    decision, found = _scan(_rule(r"(?i)zorbit now"), FRAMED * copies)
    assert decision == "allow_redacted"
    assert found["severity"] == "review" and found["defensive_context"] is True
    assert found["original_severity"] == "high"


@pytest.mark.parametrize("copies", [1, 33, 34, 400])
def test_a_bare_hit_after_the_framed_ones_gives_the_rule_its_severity_back(copies):
    decision, found = _scan(_rule(r"(?i)zorbit now"), FRAMED * copies + BARE)
    assert decision in BLOCKING
    assert _is_live(found)


@pytest.mark.parametrize("order", ["fnl", "nfl", "lfn", "lnf"])
def test_framed_negated_and_live_hits_mixed_in_any_order(order):
    parts = {"f": FRAMED, "n": NEGATED, "l": BARE}
    decision, found = _scan(_rule(r"(?i)zorbit now"), "".join(parts[c] for c in order))
    assert decision in BLOCKING
    assert _is_live(found)


@pytest.mark.parametrize("order", ["fn", "nf", "fnfn"])
def test_framed_and_negated_hits_together_stay_covered(order):
    parts = {"f": FRAMED, "n": NEGATED}
    decision, found = _scan(_rule(r"(?i)zorbit now"), "".join(parts[c] for c in order))
    assert decision == "allow_redacted"
    assert found["severity"] == "review"
    assert found.get("defensive_context") or found.get("negation_context")


def test_a_live_hit_in_the_second_alternative_of_the_rule_is_read():
    rule = _rule(r"(?i)zorbit now")
    rule["regex"] = [r"(?i)zorbit now", r"(?i)quark later"]
    decision, found = _scan(rule, FRAMED * 3 + "Then quark later arrives. ")
    assert decision in BLOCKING
    assert _is_live(found)


def test_an_unbounded_shape_fails_closed_on_a_framed_rule():
    rule = _rule(r"(?i)(w)arn \1")
    text = 'Our scanner detects examples "warn w". ' * 6000
    decision, found = _scan(rule, text)
    assert decision in BLOCKING
    assert _is_live(found)


def test_a_negation_immune_mechanism_rule_stays_open_to_framing_only():
    rule = _rule(r"(?i)zorbit now", negation_immune=True)
    framed_decision, framed = _scan(rule, FRAMED)
    assert framed_decision == "allow_redacted" and framed["defensive_context"] is True
    negated_decision, negated = _scan(rule, NEGATED)
    assert negated_decision in BLOCKING and _is_live(negated)


def test_framing_does_not_gain_the_blank_run_allowance_of_the_negation():
    rule = _rule(r"(?i)zorbit now")
    single, _ = _scan(rule, 'Our scanner detects examples "zorbit now"')
    assert single == "allow_redacted"
    for gap in ("  ", "\t", "   "):
        decision, found = _scan(rule, 'Our scanner detects' + gap + 'examples "zorbit now"')
        assert decision in BLOCKING and _is_live(found), repr(gap)


def test_a_non_mechanism_rule_is_never_downgraded_by_framing():
    decision, found = _scan(_rule(r"(?i)zorbit now", rule_id="TEST-PLAIN-001"), FRAMED)
    assert decision in BLOCKING
    assert _is_live(found)
