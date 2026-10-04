"""Ratchet for three ordinary sentences that two encoding rules block.

GLS-ENC-ALT-210 blocks a data step that says to ignore empty rows or old messages, and
GLS-CF-252 blocks a status line that says a security update was applied successfully.
Two earlier pull requests (#314, #318) tried to exclude them and lost attack wordings that
block today, because the excluded words are words an attacker can write too. The decision is
to leave the two rules as they are (tests/ACCEPTED_REVIEW.md, last section).

PERMANENT_SENTENCES is the corpus and is never shortened. KNOWN_REVIEW is the exception map:
a sentence listed there must still be blocked by the rule named beside it and by no other
rule. A sentence that is not listed there must not be blocked at all. So when a later change
makes a listed sentence scan without a block, the test fails until its entry is deleted, and
once the entry is deleted the sentence stays in the corpus and a later re-block fails the
test. Adding an entry for a new sentence means adding the sentence to the corpus too.
"""
import pytest

from sunglasses.engine import SunglassesEngine

BLOCKING = ("block", "quarantine")
CHANNELS = ["file", "message", "web_content", "tool_output"]

PERMANENT_SENTENCES = [
    "Decode the CSV input and ignore all empty rows.",
    "Decode the mail archive and ignore all messages older than thirty days.",
    "Security update applied successfully.",
]

KNOWN_REVIEW = {
    "Decode the CSV input and ignore all empty rows.": "GLS-ENC-ALT-210",
    "Decode the mail archive and ignore all messages older than thirty days.": "GLS-ENC-ALT-210",
    "Security update applied successfully.": "GLS-CF-252",
}


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def test_every_entry_is_in_the_permanent_corpus():
    assert set(KNOWN_REVIEW) <= set(PERMANENT_SENTENCES)


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("text", PERMANENT_SENTENCES)
def test_sentence_decision_matches_its_entry(engine, text, channel):
    result = engine.scan(text, channel=channel)
    if text in KNOWN_REVIEW:
        assert result.decision in BLOCKING, (
            f"{text!r} is no longer blocked on {channel}: delete its entry from KNOWN_REVIEW "
            f"and keep the sentence in PERMANENT_SENTENCES"
        )
        fired = {f["id"] if isinstance(f, dict) else f.id for f in result.findings}
        assert fired == {KNOWN_REVIEW[text]}, f"{text!r} on {channel} fires {sorted(fired)}"
    else:
        assert result.decision not in BLOCKING, (
            f"{text!r} is blocked again on {channel} after its entry was deleted"
        )
