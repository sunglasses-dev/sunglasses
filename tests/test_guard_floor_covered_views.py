"""A rule's second copy and a covered hit never leave the rule with two findings or a lowered severity.

Both the raw view and the normalized view of a text can hold the rule's hit as covered (a prohibition in
front of it) or as live. The cover check is forced here, one view at a time, so each of the four
combinations is walked whatever the text is. These tests hold, for a rule whose own hit and whose second
copy both match the text:

  A. the rule has exactly one finding in every combination,
  B. a live hit on either view ends at the rule's own severity and the decision block,
  C. the second copy stands (at its lowered severity) when the normalized view covers the rule's hit,
  D. a live hit on the normalized view replaces a covered second copy, and the finding it leaves is the
     rule's own, not the copy at its lowered severity.
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from sunglasses.engine import SunglassesEngine   # noqa: E402
from sunglasses.patterns import PATTERNS          # noqa: E402

RULE = "GLS-DFP-062"
TEXT = "aclocal.m4 does not authoritative configure.ac agent agent instruction"
PATTERN = next(p for p in PATTERNS if p["id"] == RULE)
LIVE, COVERED = None, "negation"


def _scan(raw_cover, normalized_cover, channel):
    engine = SunglassesEngine(patterns=[PATTERN], mechanisms=False, validators=False)

    def cover(mode, rx, guards, subject, match, *args):
        return match, (raw_cover if subject == TEXT else normalized_cover)

    engine._resolve_cover = cover
    return engine.scan(TEXT, channel=channel)


@pytest.mark.parametrize("channel", ["file", "web_content"])
@pytest.mark.parametrize("raw_cover, normalized_cover", [
    (LIVE, LIVE), (LIVE, COVERED), (COVERED, LIVE), (COVERED, COVERED),
])
def test_the_rule_has_one_finding_in_every_combination(raw_cover, normalized_cover, channel):
    result = _scan(raw_cover, normalized_cover, channel)
    assert len([f for f in result.findings if f["id"] == RULE]) == 1


@pytest.mark.parametrize("channel", ["file", "web_content"])
@pytest.mark.parametrize("raw_cover, normalized_cover", [(LIVE, LIVE), (COVERED, LIVE)])
def test_a_live_hit_ends_at_the_rules_own_severity(raw_cover, normalized_cover, channel):
    result = _scan(raw_cover, normalized_cover, channel)
    own = [f for f in result.findings if f["id"] == RULE][0]
    assert own["severity"] == PATTERN["severity"]
    assert not own.get("defensive_context") and not own.get("negation_context")
    assert result.decision == "block"


@pytest.mark.parametrize("channel", ["file", "web_content"])
def test_the_second_copy_stands_when_the_normalized_view_covers_the_hit(channel):
    result = _scan(LIVE, COVERED, channel)
    own = [f for f in result.findings if f["id"] == RULE][0]
    assert own["severity"] == "medium"
    assert own.get("defensive_context")
    assert result.decision == "quarantine"
