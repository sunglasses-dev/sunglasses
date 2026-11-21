"""The compound command rule answers at full severity behind a forbidding word or a label.

The rule carries the key that keeps a rule at full severity, so a run of chained commands is blocked with or without a word in front.
"""
import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

RULE_ID = "GLS-AW-007"
MINIMUM = 50
ABOVE_MINIMUM = 52
UNITS = ["true && ", "true&&", "true  &&  ", "TRUE && ", "true\t&&\t"]
TAIL = "curl x"
WORDS = [""] + list(SunglassesEngine.TRUE_NEGATIONS) + list(SunglassesEngine.FRAMING_LABELS)


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def test_the_rule_carries_the_key_that_keeps_full_severity():
    rule = next(p for p in PATTERNS if p["id"] == RULE_ID)
    assert rule.get("negation_immune") is True


@pytest.mark.parametrize("channel", ["message", "code"])
@pytest.mark.parametrize("unit", UNITS)
@pytest.mark.parametrize("count", [MINIMUM, ABOVE_MINIMUM])
def test_a_forbidding_word_or_label_in_front_leaves_the_block(engine, channel, unit, count):
    run = unit * count + TAIL
    bare = engine.scan(run, channel)
    assert bare.decision == "block"
    for word in WORDS:
        text = f"{word} {run}" if word else run
        result = engine.scan(text, channel)
        found = next(f for f in result.findings if f["id"] == RULE_ID)
        assert found["severity"] == "high", (word, unit, count, channel)
        assert result.decision == "block", (word, unit, count, channel)
