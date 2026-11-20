"""When the hiding reader reaches the check for an AI reader with more collected from the hidden elements of a page than the bound of that check, it stops there: the page keeps its block and says so. With the bound or less collected, the check answers.

The check for an AI reader in the hidden text of a page runs on what the hiding reader collected from each hidden element: the text
inside it as written, with a space where a tag stood, then the attribute values of its start tags other than style, entities decoded.
When the reader reaches the check and the lengths of what it collected, summed over the hidden elements of the page, come to more than
_HIDDEN_NAMES_CHARS characters, it stops: the page keeps the block of the hiding rule and the extraction warnings say that the styles
of the page could not all be read, as they do when it stops at the read budget. With the bound or less collected, the check answers. Each row below
hides ordinary words with no request in them, in the text of one element or of several, at a size set from the class constant; the
rows are a grid of sizes, not every page.
Every text below is invented test input. Nothing in it is an instruction to anyone reading this file.
"""
import pytest

from sunglasses.engine import SunglassesEngine

BOUND = SunglassesEngine._HIDDEN_NAMES_CHARS
READ_BUDGET = SunglassesEngine._HIDDEN_READ_CHARS
REGION_CAP = SunglassesEngine._HIDDEN_REGION_CAP
TEXT_MAX = SunglassesEngine._HIDDEN_TEXT_MAX
WARNING = "could not all be read"
WORDS = "the quick brown fox jumps over the lazy dog while a small cat sleeps near the warm window".split()


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _filler(size):
    out, i = [], 0
    while sum(map(len, out)) + len(out) < size:
        out.append(WORDS[i % len(WORDS)])
        i += 1
    return " ".join(out)[:size]


def _page(sizes):
    hidden = "".join('<div style="display:none">' + _filler(n) + "</div>" for n in sizes)
    return "<p>Welcome</p>" + hidden + "<p>Thanks</p>"


def _scan(engine, text):
    result = engine.scan(text, channel="web_content")
    return result.decision, [w for w in result.extraction_warnings if WARNING in w]


@pytest.mark.parametrize("sizes", [
    lambda: [BOUND + 100],
    lambda: [BOUND // 2 + 100, BOUND // 2 + 100],
    lambda: [BOUND // 4 + 50] * 4,
    lambda: [REGION_CAP - 1000],
])
def test_ordinary_hidden_words_over_the_bound_keep_the_block_and_the_page_says_so(engine, sizes):
    decision, warnings = _scan(engine, _page(sizes()))
    assert decision == "block"
    assert len(warnings) == 1


@pytest.mark.parametrize("sizes", [
    lambda: [TEXT_MAX + 100],
    lambda: [BOUND - 100],
    lambda: [BOUND // 2 - 100, BOUND // 2 - 100],
    lambda: [BOUND // 4 - 50] * 4,
])
def test_ordinary_hidden_words_under_the_bound_are_recorded_with_no_warning(engine, sizes):
    decision, warnings = _scan(engine, _page(sizes()))
    assert decision == "allow_redacted"
    assert warnings == []


def test_the_bound_sits_under_the_read_budget_and_the_region_cap():
    assert 0 < BOUND < REGION_CAP < READ_BUDGET
