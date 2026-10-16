"""The hidden text rule reads a start tag that carries a hiding style the same way
whatever the tag is, however its attributes are written and however the text is
encoded.

An earlier change excused hidden start tags that hold no text of their own. The
excuse was a claim about where the tag ends, and a character reference, an
escape, a full width mark or a stray quote can move that point on the folded or
shadow copy of the text. Every family below was a way to write a hidden tag that
the excuse let through, so the rule keeps no such excuse: a hiding style on any
start tag is flagged on every documented channel, as it was before the excuse.
"""
import itertools

import pytest

from sunglasses.engine import SunglassesEngine

HI = "GLS-HI-002"
CHANNELS = ("web_content", "file")
STYLES = ("display:none", "visibility:hidden", "color:white;background:white", "color:#fff;background:#fff")
EXCUSED_TAGS = ("img", "input", "meta", "source", "track", "embed", "br", "hr", "iframe", "script")


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def flagged(engine, text, channel):
    return HI in {f["id"] for f in engine.scan(text, channel=channel).findings}


def encoded(style):
    return style.replace(":", "&#58;")


VALUE_START_FORMS = ("&#32;", "&#x20;", "&#9;", "&Tab;", "&#10;", "&NewLine;", "%20", "\\x20", "%2520", " ")
VALUE_START = [
    "<%s style=\"%s\" title=%s%s srcdoc=content %s></%s>" % (tag, encoded(style), form, quote, quote, tag)
    for tag, quote, form, style in itertools.product(
        ("iframe", "script", "img"), ('"', "'"), VALUE_START_FORMS, STYLES)
]

SEPARATOR_FORMS = ("%1e", "\\x1e", "&#x1e;", "%251e")
SEPARATOR = [
    "a\x1eb" + form + text
    for form, text in itertools.product(SEPARATOR_FORMS, VALUE_START[:60])
]

DELIMITERS = ("&#32;", "&#x20;", "&Tab;", "&#9;", "&#x9;", "&#10;", "&NewLine;", "&#47;", "&sol;", "%20", "%09",
              "%2f", "\\x20", "\\x09", "\\x2f", " ", "​", "⁠", "／")
DELIMITER = [
    "<%s %s style=\"display&#58;none\"></%s>" % (tag, attr % d, tag)
    for d, tag, attr in itertools.product(
        DELIMITERS, ("iframe", "script", "img"),
        ("a%sb=x srcdoc=content", "title=a%sb srcdoc=content", "title%s=x srcdoc=content", "title=\"a%sb\" srcdoc=content"))
]


def shadow(text):
    """Printable ASCII written as the invisible tag block, which the engine reads back."""
    return "".join(chr(ord(c) + 0xE0000) if 32 <= ord(c) <= 126 else c for c in text)


SHADOW = [shadow(t) for t in VALUE_START[:40]] + ["plain\n" + shadow(t) for t in VALUE_START[:40]]


def fullwidth_name(tag, k):
    return tag[:k] + chr(ord(tag[k]) + 0xFEE0) + tag[k + 1:]


WIDTH = [
    "<%s style=\"%s\">content</%s>" % (name, encoded(style), name)
    for tag, style in itertools.product(EXCUSED_TAGS, STYLES)
    for name in (fullwidth_name(tag, k) for k in range(len(tag)))
]

MISC = [VALUE_START[0].replace("&#32;", c) for c in ("​", "⁠", "­", "͏", "﻿")] + [
    "<%s style=\"display&#58;none\">content</%s>" % (t, t) for t in ("inрut", "sоurce", "mеta")]

# A stray quote in the text and in an unquoted value: the browser reads the quote
# as part of the value, so the later quoted attribute is not the end of the tag.
STRAY_QUOTE = [
    lead + quote + "<div a=x" + quote + "y title=" + quote + "<br>" + quote + " style=display:none>words</div>"
    for lead, quote in itertools.product(("<br>", "<img src=x>", "<input>", "<hr>"), ('"', "'"))
]

# Hiding styles written on the tags the earlier excuse covered, each way it was read.
PLAIN_TAGS = [
    "<img\talt=x\tstyle=display:none>", "<img\ralt=x\rstyle=display:none>",
    "<img\nalt=x\nstyle=display:none>", "<img\falt=x\fstyle=display:none>",
    "<div a=<br> style=display:none>words</div>", "<img alt=\">\" style=display:none>",
    "<img alt=x style=display:none>", "<input value=\"x\" style=display:none>",
    "<meta name=x content=y style=display:none>", "<IMG ALT=x STYLE=display:none>",
    "<img src=\"a.gif\" style=\"display:none\">", "<br style=\"display:none\">",
    "<iframe src=\"https://example.com/ns.html?id=X-0001\" height=\"0\" width=\"0\""
    " style=\"display:none;visibility:hidden\"></iframe>",
    "<noscript>\n  <iframe\n    src=\"https://example.com/ns.html?id=X-0001\"\n    height=\"0\"\n    width=\"0\"\n"
    "    style=\"display:none;visibility:hidden\"\n  >\n  </iframe>\n</noscript>\n",
]

FAMILIES = {
    "value_start": VALUE_START,
    "separator": SEPARATOR,
    "delimiter": DELIMITER,
    "shadow": SHADOW,
    "width": WIDTH,
    "misc": MISC,
    "stray_quote": STRAY_QUOTE,
    "plain_tags": PLAIN_TAGS,
}
CASES = [(name, text) for name, texts in FAMILIES.items() for text in texts]


def test_the_families_are_not_empty():
    assert {name: len(texts) for name, texts in FAMILIES.items()} == {
        "value_start": 240, "separator": 240, "delimiter": 228, "shadow": 80, "width": 176, "misc": 8,
        "stray_quote": 8, "plain_tags": 14}


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("family,text", CASES, ids=[f"{n}-{i}" for i, (n, _) in enumerate(CASES)])
def test_a_hiding_style_on_a_start_tag_is_flagged_however_the_tag_is_written(engine, family, text, channel):
    assert flagged(engine, text, channel)


CONTROLS = [
    "<p>" + "\"" + "<div a=x\"y title=\"<br>\" style=display:none>words</div>",
    "<div a=x\"y title=\"<br>\" style=display:none>words</div>",
    "<br><div a=xy title=\"<br>\" style=display:none>words</div>",
]


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("text", CONTROLS)
def test_the_stray_quote_controls_are_flagged(engine, text, channel):
    assert flagged(engine, text, channel)


def test_the_rule_carries_no_second_reading_of_its_regexes():
    from sunglasses.patterns import PATTERNS
    rule = next(p for p in PATTERNS if p["id"] == HI)
    assert "regex_unexempted" not in rule and "regex_unexempted_tags" not in rule
    assert rule.get("match_on") != "normalized"
    assert not any(hasattr(SunglassesEngine, name) for name in (
        "_cuts_tag_differently", "_tag_boundaries", "_compile_unexempted"))
