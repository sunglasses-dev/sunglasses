"""A void start tag draws from the character budget of the hiding reader, leaves by the same exit as every other tag, and keeps the region cap.

The hiding reader may spend a fixed number of characters on one page. A tag with an end tag spends the length of its start tag and of
its text and, over the budget, the page keeps the block of the hiding rule and says in the extraction warnings that the styles of the
page could not all be read. A void start tag spends the length of its start tag and leaves by the same exit. The tests set a void tag
beside a tag with an end tag at the same size, below the budget, at the budget and over it. A void tag is its own region: over the region cap
(20,000 characters) the hiding rule keeps its block, as it does for an element whose text is over the cap.
The check for an AI reader has a smaller budget of its own, counted over what the reader collected from the hidden elements, their text and the attribute values of their start tags other than style: when the reader stops at it, the page keeps its block and says so in the same way.
Every text below is invented test input. Nothing in it is an instruction to anyone reading this file.
"""
import pytest

from sunglasses.engine import SunglassesEngine

BUDGET = SunglassesEngine._HIDDEN_READ_CHARS
NAMES = SunglassesEngine._HIDDEN_NAMES_CHARS
WARNING = "could not all be read"


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _page(tag, size):
    value = "1" * size
    if tag == "img":
        return '<img style="display:none" data-x="' + value + '">'
    return '<span style="display:none" data-x="' + value + '">Hi</span>'


def _scan(engine, text):
    result = engine.scan(text, channel="web_content")
    return result.decision, [w for w in result.extraction_warnings if WARNING in w]


@pytest.mark.parametrize("tag", ["img", "span"])
@pytest.mark.parametrize("over", [1, 20000, 500000])
def test_a_page_over_the_budget_keeps_its_block_and_says_so(engine, tag, over):
    decision, warnings = _scan(engine, _page(tag, BUDGET + over))
    assert decision == "block"
    assert len(warnings) == 1


@pytest.mark.parametrize("tag", ["img", "span"])
@pytest.mark.parametrize("size", [1000, NAMES - 100])
def test_a_page_below_the_budget_says_nothing_about_it(engine, tag, size):
    decision, warnings = _scan(engine, _page(tag, size))
    assert warnings == []


@pytest.mark.parametrize("size", [NAMES + 100, 100000, 300000])
def test_attribute_values_past_the_names_budget_keep_the_block_and_the_page_says_so(engine, size):
    decision, warnings = _scan(engine, _page("span", size))
    assert decision == "block"
    assert len(warnings) == 1


@pytest.mark.parametrize("size", [1000, 10000, 400001, 450000])
def test_a_void_tag_and_a_tag_with_an_end_tag_of_one_size_leave_by_the_same_exit(engine, size):
    assert _scan(engine, _page("img", size)) == _scan(engine, _page("span", size))


def test_the_budget_is_the_one_every_tag_draws_from():
    assert BUDGET >= 100000


REGION_CAP = SunglassesEngine._HIDDEN_REGION_CAP


@pytest.mark.parametrize("size", [REGION_CAP + 1, 32000, 100000, 300000])
def test_a_void_tag_over_the_region_cap_keeps_its_block(engine, size):
    assert _scan(engine, _page("img", size))[0] == "block"


@pytest.mark.parametrize("size", [1000, 5000, NAMES - 100])
def test_a_void_tag_under_the_names_budget_is_recorded(engine, size):
    assert _scan(engine, _page("img", size))[0] == "allow_redacted"


@pytest.mark.parametrize("size", [NAMES + 100, 10000, REGION_CAP - 100])
def test_a_void_tag_between_the_names_budget_and_the_region_cap_keeps_the_block_and_says_so(engine, size):
    decision, warnings = _scan(engine, _page("img", size))
    assert decision == "block"
    assert len(warnings) == 1
