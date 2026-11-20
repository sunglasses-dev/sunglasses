"""A rule's gate is a cheap test a page must pass before the rule's regexes run on it (engine step 3, _rule_gates).

A gate is only allowed to be the part every regex of the rule needs. Then a page that fails it cannot match the rule, and
skipping the rule there changes no verdict. These tests are the proof: every text the rule is built to catch passes its
gate, and the engine's findings are the same with the gate on and off.
"""
import pytest

from sunglasses import _rule_gates
from sunglasses.engine import SunglassesEngine
import test_reader_directed_orders as T

ENGINE = SunglassesEngine()
RULE = "GLS-IP-009"

MUST_BLOCK = (
    [t for _, t in T.HOSTILE]
    + list(T.ORDERS_AFTER_AN_UNRELATED_NO)
    + list(T.ORDERS_STATED_AS_A_DUTY)
    + list(T.ORDERS_TO_A_BARELY_NAMED_READER)
    + list(T.MORE_ORDERS_THAT_ACT_ON_THE_PERSON)
    + list(T.ORDERS_WITH_THE_PARTS_IN_OTHER_PLACES)
)
QUIET_TEXTS = (
    list(T.QUIET.values())
    + list(T.QUIET_TWINS.values())
    + list(T.QUIET_TWINS_ABOUT_THE_ORDERS.values())
    + list(T.QUIET_READER_NAMED_NOT_ADDRESSED.values())
    + list(T.FORBIDDING_FORMS)
)


def test_every_gate_belongs_to_a_rule_that_carries_a_regex():
    for rule_id in _rule_gates.GATES:
        assert rule_id in ENGINE._rule_gate, rule_id


def test_every_text_the_rule_is_built_to_catch_passes_its_gate():
    gate = ENGINE._rule_gate[RULE]
    missed = [t[:80] for t in MUST_BLOCK if gate.search(t) is None]
    assert not missed, missed
    assert len(MUST_BLOCK) >= 70


def test_a_page_with_no_addressed_reader_does_not_pass_the_gate():
    gate = ENGINE._rule_gate[RULE]
    page = "Stainless steel blender, six blades. Add to cart for the best price. Pay with a saved card at checkout."
    assert gate.search(page) is None


@pytest.mark.parametrize("channel", T.READ_CHANNELS)
def test_the_findings_are_the_same_with_the_gate_on_and_off(channel):
    texts = MUST_BLOCK + QUIET_TEXTS
    on = [sorted(f["id"] for f in ENGINE.scan(t, channel=channel).findings) for t in texts]
    saved = dict(ENGINE._rule_gate)
    ENGINE._rule_gate.clear()
    try:
        off = [sorted(f["id"] for f in ENGINE.scan(t, channel=channel).findings) for t in texts]
    finally:
        ENGINE._rule_gate.update(saved)
    assert on == off


def _regex_runs_for_the_rule(text, channel):
    """How many times step 3 hands one of the rule's regexes a view of `text`."""
    calls = []
    real = ENGINE._eval_regex

    def spy(mode, rx, guards, subject, *args, **kwargs):
        if kwargs.get("key") == RULE:
            calls.append(mode)
        return real(mode, rx, guards, subject, *args, **kwargs)

    ENGINE._eval_regex = spy
    try:
        ENGINE.scan(text, channel="web_content")
    finally:
        del ENGINE._eval_regex
    return len(calls)


def test_the_engine_leaves_the_rules_regexes_alone_on_a_page_that_fails_the_gate():
    page = "Stainless steel blender, six blades. Add to cart for the best price. Pay with a saved card at checkout."
    assert _regex_runs_for_the_rule(page, "web_content") == 0


def test_the_engine_runs_the_rules_regexes_on_a_page_that_passes_the_gate():
    assert _regex_runs_for_the_rule(MUST_BLOCK[0], "web_content") >= 1
