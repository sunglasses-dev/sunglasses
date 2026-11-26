"""A validator that carries its own reading of markup is given the page as written, once, and never a part.

On the page road a web_content page with markup is cut into parts and every part goes through the rules. The mail-destination validator reads
blocks, tags, comments, attribute values and written forms itself, so it reads the capped page as written, once per scan, whatever the
engine does with the rest. A failing read on the page ends the scan as not complete, as a failing validator does on any text.
"""
import pytest

from sunglasses import _send_target
from sunglasses.engine import SunglassesEngine
from sunglasses.validators import VALIDATORS

RULE = "GLS-STRUCT-007"
ENGINE = SunglassesEngine()

LINKED = "<html><body><a href='https://paypal.com'>p</a>%s</body></html>"
ONE_BLOCK = LINKED % "<p>Please send your files to team@paypal-secure.org today.</p>"
TWO_BLOCKS = LINKED % "\nSend your files\n\nteam@paypal-secure.org\n"


def _found(text, channel="web_content"):
    return [f for f in ENGINE.scan(text, channel=channel).findings if f["id"] == RULE]


def test_the_validator_carries_the_flag_on_its_class_and_no_other_validator_does_by_accident():
    carriers = [v.id for v in VALIDATORS if getattr(v, "reads_the_page_as_written", False)]
    assert carriers == [RULE]


def test_a_page_read_as_parts_gives_the_finding_once():
    hits = _found(ONE_BLOCK)
    assert len(hits) == 1 and hits[0]["evidence"]["looks_like"] == "paypal.com"


def test_the_reader_is_given_the_page_as_written_once_and_never_a_part(monkeypatch):
    seen = []
    real = _send_target.read

    def spy(text):
        seen.append(text)
        return real(text)
    monkeypatch.setattr(_send_target, "read", spy)
    assert len(_found(ONE_BLOCK)) == 1
    assert seen == [ONE_BLOCK]


def test_a_verb_and_an_address_in_two_blocks_stay_apart_on_a_page_read_as_parts():
    assert _found(TWO_BLOCKS) == []


@pytest.mark.parametrize("channel", ["web_content", "file"])
def test_a_page_with_no_markup_and_a_file_are_read_as_before(channel):
    text = "Please send your files to team@paypal-secure.org today. See https://www.paypal.com/help ."
    assert len(_found(text, channel)) == 1


def test_a_failing_read_on_the_page_ends_the_scan_not_complete(monkeypatch):
    def broken(text):
        raise ValueError("boom")
    monkeypatch.setattr(_send_target, "read", broken)
    result = ENGINE.scan(ONE_BLOCK, channel="web_content")
    assert result.extraction_complete is False
    assert any(RULE in w and "ValueError" in w for w in result.extraction_warnings)
    assert [f for f in result.findings if f["id"] == RULE] == []


def test_a_failing_read_on_a_text_with_no_markup_ends_the_scan_not_complete_the_same_way(monkeypatch):
    def broken(text):
        raise ValueError("boom")
    monkeypatch.setattr(_send_target, "read", broken)
    result = ENGINE.scan("Please send your files to team@paypal-secure.org today.", channel="web_content")
    assert result.extraction_complete is False
    assert any(RULE in w for w in result.extraction_warnings)
