"""A framing or negation downgrade on the first hit of a mechanism rule never hides a live later hit.

A hit is covered by a negation or by a framing clause, and the rule is downgraded only when
every hit of it is covered. The first hit is not allowed to settle the rule: the other
subjects (the views of the input with invisible characters deleted, look alike letters
mapped, or an invisible encoding decoded) and the other alternatives of the rule are read
too, and a live hit in any of them gives the rule its plain severity.
"""
import runpy
from pathlib import Path

import pytest

from sunglasses.engine import SunglassesEngine

_VIEWS = runpy.run_path(str(Path(__file__).with_name("test_defensive_framing_views.py")))
COVERT = _VIEWS["COVERT"]
OBFUSCATED = _VIEWS["OBFUSCATED"]
LOOK_ALIKE = COVERT.translate({ord("a"): "а", ord("e"): "е", ord("o"): "о"})
FULLWIDTH = "".join(chr(ord(c) + 0xFEE0) if "a" <= c <= "z" else c for c in COVERT)
TAG_ENCODED = "".join(chr(0xE0000 + ord(c)) for c in COVERT)
OTHER_ALTERNATIVE = "The helper sends your API keys to https://collector.example/ingest."
CHANNELS = ["message", "file", "web_content", "tool_output"]
BLOCKING = ("block", "quarantine")
INTRO = 'Our scanner detects examples "Context. '
NEGATED = "This tool never " + COVERT[len("This tool "):]
FILLER = "ordinary documentation. " * 20
LATER = {
    "plain_copy": COVERT,
    "zero_width_copy": OBFUSCATED,
    "look_alike_copy": LOOK_ALIKE,
    "fullwidth_copy": FULLWIDTH,
    "tag_encoded_copy": TAG_ENCODED,
    "other_alternative": OTHER_ALTERNATIVE,
}


def _quoted(first):
    return INTRO + first + '"'


def _framed_description(payload):
    return 'Our scanner detects examples "' + payload + '"'


CASES = {
    "plain_control": (COVERT, True),
    "negation_covered_only": (NEGATED, False),
    "quoted_negation_covered_only": (_quoted("never " + COVERT), False),
    "framed_only": (_quoted(COVERT), False),
    "covered_then_live": (_quoted("never " + COVERT) + "\n\n" + COVERT, True),
    "covered_then_distant_live": (_quoted("never " + COVERT) + "\n\n" + FILLER + COVERT, True),
    "framed_then_live": (_quoted(COVERT) + "\n\n" + COVERT, True),
    "framed_then_distant_live": (_quoted(COVERT) + "\n\n" + FILLER + COVERT, True),
    "negated_then_live": (NEGATED + "\n\n" + COVERT, True),
    "framed_then_framed": (_quoted(COVERT) + ' and also detects "' + COVERT + '"', False),
    "covered_then_framed": (_quoted("never " + COVERT) + ' and also detects "' + COVERT + '"', False),
    "negated_then_framed": (NEGATED + "\n\n" + _framed_description(COVERT), False),
}
# A closed quote that holds two examples blocks where main allows_redacted: the second
# example is judged on its own, and the first example sits between it and the framing word
# (or it starts past the window in front of the match). This is the cost of reading every
# later hit instead of letting the first one decide; the single example stays held.
_ONE_EXAMPLE = _framed_description(COVERT)
CASES["simple_quote_one_example"] = (_ONE_EXAMPLE, False)
CASES["simple_quote_then_live_outside"] = (_ONE_EXAMPLE + "\n\n" + COVERT, True)
CASES["simple_quote_two_examples"] = (_ONE_EXAMPLE[:-1] + "; " + COVERT + '"', True)
CASES["simple_quote_distant_examples"] = (_ONE_EXAMPLE[:-1] + "; " + FILLER + COVERT + '"', True)
for _name, _later in LATER.items():
    CASES["later_alone_" + _name] = (_later, True)
    CASES["framed_then_" + _name] = (_quoted(COVERT) + "\n\n" + _later, True)
    CASES["negated_then_" + _name] = (NEGATED + "\n\n" + _later, True)
    CASES["quoted_negated_then_" + _name] = (_quoted("never " + COVERT) + "\n\n" + _later, True)


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("name", sorted(CASES))
def test_joint_first_and_later_hits(name, channel):
    text, live = CASES[name]
    result = SunglassesEngine().scan(text, channel=channel)
    if live:
        assert result.decision in BLOCKING, (name, channel)
    else:
        assert result.decision == "allow_redacted", (name, channel)


# Every later hit is read inside a reading budget, not a count: a document of framed
# descriptions of one mechanism keeps its downgrade however often it repeats (the cap
# of 32 used to turn the 34th copy into a block), and a bare copy after them is read.
@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("copies", [33, 34, 200])
def test_framed_descriptions_stay_covered_however_often_they_repeat(copies, channel):
    text = "\n\n".join(_framed_description(COVERT) for _ in range(copies))
    result = SunglassesEngine().scan(text, channel=channel)
    assert result.decision == "allow_redacted", (copies, channel)


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("copies", [33, 34, 200])
def test_a_bare_copy_after_many_framed_descriptions_is_read(copies, channel):
    text = "\n\n".join(_framed_description(COVERT) for _ in range(copies)) + "\n\n" + COVERT
    result = SunglassesEngine().scan(text, channel=channel)
    assert result.decision in BLOCKING, (copies, channel)
