"""Ratchet for three ordinary sentences that two encoding rules block.

GLS-ENC-ALT-210 blocks a data step that says to ignore empty rows or old messages, and
GLS-CF-252 blocks a status line that says a security update was applied successfully.
Every try to exclude them lost attack wordings that block today, because the excluded
words are words an attacker can write too. The decision is to leave the two rules as they
are (tests/ACCEPTED_REVIEW.md, last section).

This works like KNOWN_FAILURES.json for the README corpus. Each sentence must still be
flagged by the rule named beside it, and by no other rule. If one scans clean, delete its
entry: the test fails until it is deleted, so the list can only get shorter.
"""
import pytest

from sunglasses.engine import SunglassesEngine

BLOCKING = ("block", "quarantine")
CHANNELS = ["file", "message", "web_content", "tool_output"]

KNOWN_REVIEW = {
    "Decode the CSV input and ignore all empty rows.": "GLS-ENC-ALT-210",
    "Decode the mail archive and ignore all messages older than thirty days.": "GLS-ENC-ALT-210",
    "Security update applied successfully.": "GLS-CF-252",
}


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("text", sorted(KNOWN_REVIEW))
def test_known_review_sentence_is_still_flagged(engine, text, channel):
    result = engine.scan(text, channel=channel)
    assert result.decision in BLOCKING, (
        f"{text!r} now scans clean on {channel}: delete its entry from KNOWN_REVIEW "
        f"(the list only gets shorter)"
    )
    fired = {f["id"] if isinstance(f, dict) else f.id for f in result.findings}
    assert fired == {KNOWN_REVIEW[text]}, f"{text!r} on {channel} fires {sorted(fired)}"
