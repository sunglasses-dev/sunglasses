"""The GLS-SD -API siblings: secrets arriving in the RESULT direction.

Four properties, and the last two are the ones that make the first two mean
something:

  1. each sibling FIRES on its own shape, in all three carriers
  2. near misses stay clean
  3. no PARENT changed on any channel it already had  (the no-widening proof)
  4. removing a sibling turns its own fixture red      (the mutation proof)

Property 3 is the whole reason this shape of change is allowed at all. A sibling
that also "improved" the predicate would make parent and sibling disagree on the
channels they share, and nothing above this file would notice.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses.engine import SunglassesEngine          # noqa: E402
from sunglasses.patterns import PATTERNS                 # noqa: E402
import sd_api_sibling_rows as rows                       # noqa: E402

RESULT_CHANNELS = ["api_response", "agent_input"]
PARENT_CHANNELS = ["file", "log_memory", "message", "web_content", "code"]


def _findings(engine, text, channel):
    result = engine.scan(text, channel=channel)
    data = result if isinstance(result, dict) else result.to_dict()
    return data.get("decision"), sorted(f["id"] for f in (data.get("findings") or []))


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


# ── 1. every sibling fires, in every carrier ────────────────────────────────

@pytest.mark.parametrize("rule_id", sorted(rows.TOKENS))
@pytest.mark.parametrize("carrier", sorted(rows.CARRIERS))
def test_the_result_direction_mirrors_the_file_direction(engine, rule_id, carrier):
    """The REAL property: the same bytes get the same answer in both directions.

    Not "this sibling reports its own id". The parents shadow each other and
    always have: GLS-SD-001's predicate is a superset that already covers the
    Slack and Google shapes, and dedup is severity-ranked, so on a `file` today
    a Slack token reports GLS-SD-001 and never GLS-SD-007. A test demanding each
    sibling name itself would fail on a FAITHFUL port and pass only on one that
    had changed the parents' relative behaviour, which is the thing forbidden
    here. Measured: 8 of 8 siblings mirror their parent exactly.

    So the assertion is equality with the parent lane, suffixes aside. That is
    what "a sibling only adds channels" means, stated as something a machine can
    check.
    """
    text = rows.CARRIERS[carrier](rows.TOKENS[rule_id])
    parent_decision, parent_ids = _findings(engine, text, "file")
    result_decision, result_ids = _findings(engine, text, "api_response")
    expected = sorted(i + "-API" for i in parent_ids if i.startswith("GLS-SD-"))
    got = sorted(i for i in result_ids if i.startswith("GLS-SD-"))
    assert got == expected, (
        f"{carrier}: file lane reported {parent_ids}, result lane reported "
        f"{result_ids}. The two directions must agree on the same bytes.")
    assert result_decision == parent_decision == "block"


def test_the_gap_this_closes_was_real(engine):
    """The parent still does not reach api_response, which is WHY the sibling exists.

    Asserted rather than assumed: if a parent were ever widened to cover this
    channel, the sibling becomes redundant and somebody should find out here.
    """
    parents = {p["id"]: p for p in PATTERNS}
    for rule_id in rows.TOKENS:
        parent = parents[rule_id[: -len("-API")]]
        assert "api_response" not in parent["channel"], (
            f"{parent['id']} now carries api_response itself, so {rule_id} is "
            f"redundant. That is a widened parent and this pattern forbids it.")


# ── 2. near misses stay clean ───────────────────────────────────────────────

@pytest.mark.parametrize("text", rows.NEAR_MISSES)
def test_near_misses_stay_clean(engine, text):
    for channel in RESULT_CHANNELS:
        _, ids = _findings(engine, text, channel)
        sd = [i for i in ids if i.startswith("GLS-SD-")]
        assert not sd, f"{sd} fired on a near miss in {channel}: {text[:60]!r}"


# ── the disclosed limit, pinned ─────────────────────────────────────────────

@pytest.mark.parametrize("rule_id", sorted(rows.VENDOR_EXAMPLES))
def test_vendor_examples_block_and_that_is_the_disclosed_limit(engine, rule_id):
    """Vendor documentation examples BLOCK in a tool result. On purpose.

    The parent predicate is copied verbatim and the parent blocks these in a
    file today, so the sibling blocks them in a result. Excluding them would
    write an evasion recipe into the rule: anyone who shapes a real key like a
    documented example would pass.

    Pinned in BOTH directions. If a change makes these pass, this goes red and
    the decision gets made deliberately rather than discovered by a user.
    """
    text = rows.tool_result(rows.VENDOR_EXAMPLES[rule_id])
    decision, ids = _findings(engine, text, "api_response")
    assert rule_id in ids
    assert decision == "block"


# ── 3. the no-widening proof ────────────────────────────────────────────────

# ── 3b. the channel set, exactly, and proven through the sibling alone ──────

# THE REVIEWED EXPECTATION, written down rather than derived from the rule it is
# meant to check. Deriving it ("api_response + agent_input, plus log_memory when
# the parent has it") would restate the implementation in the test, so a change
# to either would move both and the check would agree with itself forever.
#
# ASTRA's R-B1, 2026-09-14: the subset assertion below permitted deleting a
# declared channel, and 14 of 30 mutants survived because of it. Removing
# `agent_input` from all eight flips 8/8 public engine fixtures from block to
# allow and loses 14 secret findings, so a narrowed sibling is a real coverage
# loss rather than a tidier declaration.
EXPECTED_CHANNELS = {
    "GLS-SD-001-API": {"api_response", "log_memory", "agent_input"},
    "GLS-SD-002-API": {"api_response", "log_memory", "agent_input"},
    "GLS-SD-003-API": {"api_response", "log_memory", "agent_input"},
    "GLS-SD-004-API": {"api_response", "log_memory", "agent_input"},
    "GLS-SD-006-API": {"api_response", "log_memory", "agent_input"},
    "GLS-SD-007-API": {"api_response", "log_memory", "agent_input"},
    # 008 and 009 parents carry no `log_memory`, so their siblings do not
    # either: granting it would be new coverage outside the result direction
    # wearing a sibling's name.
    "GLS-SD-008-API": {"api_response", "agent_input"},
    "GLS-SD-009-API": {"api_response", "agent_input"},
}

# Every channel any sibling declares. The negative half of the exact set is
# checked against this, so an ADDED channel fails as loudly as a removed one.
ALL_DECLARED = sorted(set().union(*EXPECTED_CHANNELS.values()))


def test_the_expectation_covers_every_sibling():
    """The table cannot silently stop describing the family.

    A ninth sibling with no row here would otherwise be checked by nothing,
    which is how an exact-set assertion quietly becomes a partial one.
    """
    assert set(EXPECTED_CHANNELS) == set(rows.TOKENS), (
        "EXPECTED_CHANNELS and the fixture rows disagree about who the "
        "siblings are: "
        f"{sorted(set(EXPECTED_CHANNELS) ^ set(rows.TOKENS))}")


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_CHANNELS))
def test_the_declared_channel_set_is_exactly_what_it_should_be(rule_id):
    """Equality, not subset. The subset form permitted every deletion."""
    by_id = {p["id"]: p for p in PATTERNS}
    declared = set(by_id[rule_id]["channel"])
    assert declared == EXPECTED_CHANNELS[rule_id], (
        f"{rule_id} declares {sorted(declared)}; the reviewed set is "
        f"{sorted(EXPECTED_CHANNELS[rule_id])}. Missing "
        f"{sorted(EXPECTED_CHANNELS[rule_id] - declared)}, unexpected "
        f"{sorted(declared - EXPECTED_CHANNELS[rule_id])}.")


def _sibling_only_engine(rule_id):
    """An engine carrying exactly one rule: this sibling.

    THE ISOLATION IS THE POINT. GLS-SD-001's predicate already covers the Slack
    and Google shapes, so a token fired through the full ruleset can be reported
    by the parent or by an earlier sibling while this one does nothing at all. A
    finding is then evidence about the family, not about the rule under test.
    One rule in the engine means the finding can only have come from it.
    """
    by_id = {p["id"]: p for p in PATTERNS}
    return SunglassesEngine(patterns=[by_id[rule_id]], mechanisms=False)


@pytest.mark.parametrize("channel", ALL_DECLARED)
@pytest.mark.parametrize("rule_id", sorted(EXPECTED_CHANNELS))
def test_each_declared_channel_fires_through_this_sibling_alone(rule_id, channel):
    """Positive coverage per declared channel, and silence on the rest.

    Both halves together are what makes the set EXACT in behaviour rather than
    only in the declaration. A deleted channel fails the positive half; an added
    one fails the negative half; and neither can be satisfied by the parent,
    because the parent is not in this engine.
    """
    engine = _sibling_only_engine(rule_id)
    text = rows.CARRIERS["tool_result"](rows.TOKENS[rule_id])
    fired = {f["id"] for f in engine.scan(text, channel).findings}

    if channel in EXPECTED_CHANNELS[rule_id]:
        assert rule_id in fired, (
            f"{rule_id} declares {channel} and did not fire on it with only "
            f"this rule loaded. A declared channel that nothing reaches is a "
            f"claim the engine does not honour.")
    else:
        assert rule_id not in fired, (
            f"{rule_id} fired on {channel}, which it does not declare. A rule "
            f"reaching a channel outside its declaration is coverage nobody "
            f"reviewed.")


# ── 4. the mutation proof ───────────────────────────────────────────────────

@pytest.mark.parametrize("rule_id", sorted(rows.TOKENS))
def test_removing_every_sibling_reopens_the_gap(rule_id):
    """Delete the siblings, watch the shape go undetected again.

    Per-rule deletion is the wrong mutation for this set, and finding that out
    is the point. GLS-SD-001's predicate already covers the Slack and Google
    shapes, so deleting GLS-SD-007-API alone leaves its token still blocked by
    GLS-SD-001-API, and a per-rule mutation would look like a passing proof
    while proving nothing. That is the shape of every weak test I have written
    tonight.

    The honest mutation is the set: with all eight gone the token must be
    allowed on api_response again, which is precisely the gap this PR closes.
    """
    siblings = {p["id"] for p in PATTERNS
                if p["id"].startswith("GLS-SD-") and p["id"].endswith("-API")}
    engine = SunglassesEngine(patterns=[p for p in PATTERNS
                                        if p["id"] not in siblings])
    text = rows.tool_result(rows.TOKENS[rule_id])
    decision, ids = _findings(engine, text, "api_response")
    assert not [i for i in ids if i.startswith("GLS-SD-")], (
        f"{rule_id}'s shape is still detected on api_response with every sibling "
        f"removed, so this PR is not what closes it.")
    assert decision != "block"


@pytest.mark.parametrize("rule_id", ["GLS-SD-007-API", "GLS-SD-008-API"])
def test_the_shadowed_siblings_still_carry_their_shape(rule_id):
    """The two that never report their own id are not decoration.

    GLS-SD-007-API and -008-API are outranked by GLS-SD-001-API, exactly as
    their parents are outranked on `file`. Remove the rule that shadows them and
    they fire, which is what makes them real coverage rather than a rule that
    can never matter: if GLS-SD-001's predicate ever narrows, these hold the
    shape instead of it silently going undetected.
    """
    engine = SunglassesEngine(patterns=[p for p in PATTERNS
                                        if p["id"] != "GLS-SD-001-API"])
    _, ids = _findings(engine, rows.tool_result(rows.TOKENS[rule_id]),
                       "api_response")
    assert rule_id in ids
