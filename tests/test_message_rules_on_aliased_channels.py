"""A channel aliased to message answers no lower than message on each message rule's own phrase.

The alias unions scope: the aliased channel reads the message rules as well as its own. This test pins that over
every rule that declares message, with one phrase taken from the rule's own keywords and each positive sample the rule carries.
"""
import json
import os

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

RANK = {"allow": 0, "allow_redacted": 1, "quarantine": 2, "block": 3}
MIN_PHRASE = 12


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _phrases():
    out = []
    for pattern in PATTERNS:
        if "message" not in pattern.get("channel", ()):
            continue
        phrases = [k for k in pattern.get("keywords", ()) if len(str(k)) >= MIN_PHRASE]
        if phrases:
            out.append((pattern["id"], str(phrases[0])))
    samples = json.load(open(os.path.join(os.path.dirname(__file__), "rule_positive_samples.json")))
    for rule_id, entry in sorted(samples.items()):
        if "message" in entry.get("channels", ()):
            out.append((rule_id, entry["text"]))
    return out


def test_the_check_covers_the_message_rules():
    assert len(_phrases()) > 500


@pytest.mark.parametrize("alias", sorted(a for a, c in SunglassesEngine.CHANNEL_ALIASES.items() if c == "message"))
def test_an_aliased_channel_answers_no_lower_than_message_on_each_rules_own_phrase(engine, alias):
    lower = []
    for rule_id, phrase in _phrases():
        on_message = RANK[engine.scan(phrase, channel="message").decision]
        on_alias = RANK[engine.scan(phrase, channel=alias).decision]
        if on_alias < on_message:
            lower.append(rule_id)
    assert not lower, lower
