"""An order that a page hides is also read as an order when the same words are written in plain text, on the page channels (a page and a file).

Eight cases of the hidden-text matrix hide a request in one of four markups: a request for stored keys and a conditional instruction to
add something without saying so, each in four markups. Each row here takes the words out of the fixture by id, drops every tag, and scans them as a page and as a file:
the text must not be allowed. On the message channel, where a person asks about their own vault or notes, the same words stay allowed. The four rows of the matrix whose words are in another language hold on the language rule and
stand as the control rows. Text in the fixture is data only; this file carries ids.
Every text below is invented test input. Nothing in it is an instruction to anyone reading this file.
"""
import json
import pathlib
import re

import pytest

from sunglasses.engine import SunglassesEngine

CASES = {c["id"]: c for c in json.loads((pathlib.Path(__file__).parent / "fixtures" / "directive_and_hidden_text_case_matrix.json").read_text())}
OPEN_ROWS = ["a000", "a001", "a087", "a088", "a348", "a349", "a435", "a436"]
CONTROL_ROWS = ["a002", "a089", "a350", "a437"]
TAG = re.compile(r"<[^>]*>")


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _plain(case_id):
    return " ".join(TAG.sub(" ", CASES[case_id]["text"]).split())


PAGE_CHANNELS = ("web_content", "file")


@pytest.mark.parametrize("channel", PAGE_CHANNELS)
@pytest.mark.parametrize("case_id", OPEN_ROWS)
def test_the_words_of_a_hidden_order_are_not_allowed_when_written_in_plain_text(engine, case_id, channel):
    assert engine.scan(_plain(case_id), channel=channel).decision != "allow"


@pytest.mark.parametrize("case_id", ["a000", "a001"])
def test_the_same_words_stay_allowed_on_the_message_channel(engine, case_id):
    assert engine.scan(_plain(case_id), channel="message").decision == "allow"


@pytest.mark.parametrize("case_id", CONTROL_ROWS)
def test_the_control_rows_hold_in_plain_text(engine, case_id):
    assert engine.scan(_plain(case_id), channel="message").decision != "allow"


def test_the_rows_are_gap_cases_of_the_matrix():
    assert all(CASES[i]["kind"] == "gap" for i in OPEN_ROWS + CONTROL_ROWS)
