"""The floor copy of a rule never hides what the rule finds on its own.

A rule that carries an exception keeps a second copy without it. That copy is a last resort: it enters
for a rule that has no finding of its own after every path has run, and it never marks the rule as
seen for a later path. These tests hold:

  A. three texts on which the rule's own finding comes from the normalized view: the rule keeps its
     own severity and the decision stays block,
  B. for each shipped rule with an exception, the text built from the rule in front of and behind each of
     its exception words, on all five channels: the decision with the second copy is never lower than
     the decision without it,
  C. the second copy adds at most one finding for its rule,
  D. every second copy of a shipped rule compiles, none is dropped silently.
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from _floor_quiet_pin import QUIET_IDS                                                                  # noqa: E402
from sunglasses.engine import SunglassesEngine, _GUARD_FLOOR_EXTRA, _guard_floor_twin, _guard_free_source  # noqa: E402
from sunglasses.patterns import PATTERNS                                                               # noqa: E402
from test_guard_floor import GUARDED, _case                                                            # noqa: E402

CHANNELS = ("message", "file", "web_content", "tool_output", "api_response")
RANK = {"allow": 0, "allow_redacted": 1, "quarantine": 2, "block": 3}

# (rule, text): a rule's own finding is made on the normalized view of each of these.
OWN_FINDING = [
    ("GLS-DFP-062", "aclocal.m4 does not authoritative configure.ac agent agent instruction"),
    ("GLS-IDP-008", "do not includeauthorization bearer oauth-protected-resource aiassistant ignore previous"),
    ("GLS-IDP-008", "oauth-protected-resource aiassistant ignore previous do not includeauthorization bearer"),
]


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


@pytest.mark.parametrize("rule_id, text", OWN_FINDING)
@pytest.mark.parametrize("channel", ["file", "web_content"])
def test_a_rule_keeps_its_own_finding_when_the_second_copy_also_matches(engine, rule_id, text, channel):
    result = engine.scan(text, channel=channel)
    own = [f for f in result.findings if f["id"] == rule_id]
    assert len(own) == 1
    assert not own[0].get("defensive_context")
    assert own[0]["severity"] == next(p for p in PATTERNS if p["id"] == rule_id)["severity"]
    assert result.decision == "block"


def _without_second_copy(engine):
    engine._floor_walk = lambda due, findings: iter(())
    engine._floor_entry = lambda pid: None
    return engine


@pytest.mark.parametrize("rule_id", sorted(p["id"] for p in GUARDED))
def test_the_second_copy_never_lowers_a_decision(rule_id):
    pattern, _plain, with_copy, base, guards = _case(rule_id)
    if base is None:
        pytest.skip("no text for this rule")
    _channel, attack = base
    without_copy = _without_second_copy(SunglassesEngine(patterns=[pattern], mechanisms=False, validators=False))
    for guard in guards[:6]:
        for text in (attack + " " + guard, guard + " " + attack):
            for channel in CHANNELS:
                if channel not in (pattern.get("channel") or CHANNELS):
                    continue
                a = RANK[with_copy.scan(text, channel=channel).decision]
                b = RANK[without_copy.scan(text, channel=channel).decision]
                assert a >= b, (rule_id, channel)


@pytest.mark.parametrize("rule_id", sorted(p["id"] for p in GUARDED))
def test_the_second_copy_adds_at_most_one_finding_for_its_rule(rule_id):
    pattern, _plain, with_copy, base, guards = _case(rule_id)
    if base is None:
        pytest.skip("no text for this rule")
    channel, attack = base
    for guard in guards[:6]:
        for text in (attack + " " + guard, guard + " " + attack):
            found = [f for f in with_copy.scan(text, channel=channel).findings if f["id"] == rule_id]
            assert len(found) <= 1, (rule_id, len(found))


def test_every_second_copy_of_a_shipped_rule_compiles():
    engine = SunglassesEngine()
    twinned = 0
    for pattern in PATTERNS:
        if _guard_floor_twin(pattern) is None:
            continue
        twinned += 1
        extra = pattern["id"] in _GUARD_FLOOR_EXTRA
        sources = [s for s in (_guard_free_source(o, extra) for o in pattern["regex"]) if s is not None]
        entry = engine._floor_entry(pattern["id"])
        if pattern["id"] in QUIET_IDS:
            assert entry is None, pattern["id"]          # pinned in tests/_floor_quiet_pin.py: no copy at all
            continue
        assert entry is not None, pattern["id"]
        assert len(entry[1]) == len(sources), pattern["id"]
    assert twinned
