"""Crossing spans: ASTRA's R5-1 on #173 round 5.

The ownership sweep assumed the matched intervals NEST -- that a container
always sorts before what it contains and can be popped once something reaches
farther right. Intervals from different rules CROSS. An Anthropic match
[0,49), a JWT match [10,91) that crosses it, and an AWS match [29,49) inside
the Anthropic one: the JWT's farther-right end evicted the Anthropic entry, so
when the AWS match arrived its owner was gone and the receipt named AWS where
ANTHROPIC belonged.

Every one of these still DENIED. What broke is the promise that the sweep and
the quadratic scan it replaced decide identically -- eight of these
twenty-four shapes reported a different rule in the receipt, and a receipt that
names the wrong rule is what somebody reads when they ask which format leaked.

The fixtures are ASTRA's own, byte for byte, but they are stored BASE64 and
decoded here. Two of them carry Stripe-shaped bodies and GitHub's push
protection refused the branch, which is the correct answer: a product whose
whole job is noticing credential-shaped strings should not commit any. The
recorded sha256 of each decoded fixture is asserted, so the encoding cannot
drift from what ASTRA measured.

The expectations were MEASURED against the round-4 implementation -- the slow
one that was correct -- and all 24 agree with it, which is the equivalence
being asserted rather than the sweep agreeing with itself.
"""
import base64
import hashlib
import json
import pathlib

import pytest

from sunglasses.firewall import run_hook, starter_policy_text

_ENCODED = json.loads(
    (pathlib.Path(__file__).resolve().parent / "fixtures"
     / "crossing_spans.b64.json").read_text())


def fixture(name):
    """Decode one fixture and prove it is the one ASTRA measured."""
    entry = _ENCODED[name]
    raw = base64.b64decode(entry["b64"])
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"], (
        f"{name} does not match the digest recorded from ASTRA's fixture")
    return raw.decode()

# Measured on the repaired head and verified identical to round 4 (e727ee0)
# for all 24, by running both through run_hook and comparing terminal records.
EXPECTED_TERMINAL_RULE = {
    "CROSS-ANTHROPIC-ANTHROPIC": "GLS-FW-SEC-ANTHROPIC",
    "CROSS-ANTHROPIC-AWS": "GLS-FW-SEC-ANTHROPIC",
    "CROSS-ANTHROPIC-GITHUB": "GLS-FW-SEC-ANTHROPIC",
    "CROSS-ANTHROPIC-GOOGLE": "GLS-FW-SEC-ANTHROPIC",
    "CROSS-ANTHROPIC-SLACK": "GLS-FW-SEC-ANTHROPIC",
    "CROSS-ANTHROPIC-STRIPE": "GLS-FW-SEC-ANTHROPIC",
    "CROSS-GOOGLE-ANTHROPIC": "GLS-FW-SEC-ANTHROPIC",
    "CROSS-GOOGLE-AWS": "GLS-FW-SEC-GOOGLE",
    "CROSS-GOOGLE-GITHUB": "GLS-FW-SEC-GOOGLE",
    "CROSS-GOOGLE-GOOGLE": "GLS-FW-SEC-GOOGLE",
    "CROSS-GOOGLE-SLACK": "GLS-FW-SEC-SLACK",
    "CROSS-GOOGLE-STRIPE": "GLS-FW-SEC-GOOGLE",
    "CROSS-OPENAI-ANTHROPIC": "GLS-FW-SEC-OPENAI",
    "CROSS-OPENAI-AWS": "GLS-FW-SEC-OPENAI",
    "CROSS-OPENAI-GITHUB": "GLS-FW-SEC-OPENAI",
    "CROSS-OPENAI-GOOGLE": "GLS-FW-SEC-OPENAI",
    "CROSS-OPENAI-SLACK": "GLS-FW-SEC-OPENAI",
    "CROSS-OPENAI-STRIPE": "GLS-FW-SEC-OPENAI",
    "CROSS-SLACK-ANTHROPIC": "GLS-FW-SEC-ANTHROPIC",
    "CROSS-SLACK-AWS": "GLS-FW-SEC-SLACK",
    "CROSS-SLACK-GITHUB": "GLS-FW-SEC-GITHUB",
    "CROSS-SLACK-GOOGLE": "GLS-FW-SEC-SLACK",
    "CROSS-SLACK-SLACK": "GLS-FW-SEC-SLACK",
    "CROSS-SLACK-STRIPE": "GLS-FW-SEC-SLACK",
}


def _terminal(text, home):
    (home / "policy.yaml").write_text(starter_policy_text())
    run_hook(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "WebFetch",
                         "tool_input": {"url": "https://review.invalid",
                                        "prompt": text}}), home=home)
    records = [json.loads(line)
               for path in (home / "receipts").glob("*.jsonl")
               for line in path.read_text().splitlines()]
    decisions = [r for r in records if r.get("kind") == "decision"]
    assert decisions, "the hook wrote no terminal record"
    return decisions[-1]


@pytest.mark.parametrize("name", sorted(EXPECTED_TERMINAL_RULE))
def test_a_crossing_span_does_not_evict_a_containing_owner(name, tmp_path):
    """All 24, not only the 8 that differed. A row that exists only where the
    bug showed leaves the other sixteen free to drift next time."""
    record = _terminal(fixture(name), tmp_path)
    assert record["decision"] == "deny", record
    assert record["rule_id"] == EXPECTED_TERMINAL_RULE[name], (
        f"{name}: the receipt names {record['rule_id']}, and the span belongs "
        f"to {EXPECTED_TERMINAL_RULE[name]}")


@pytest.mark.parametrize("name,rule", [("CROSS-ANTHROPIC-AWS", "GLS-FW-SEC-ANTHROPIC"),
                                       ("CROSS-OPENAI-ANTHROPIC", "GLS-FW-SEC-OPENAI")])
def test_the_two_blocking_shapes_by_name(name, rule, tmp_path):
    """ASTRA's two named controls, spelled out separately from the table so a
    future edit to the table cannot quietly drop them."""
    record = _terminal(fixture(name), tmp_path)
    assert (record["decision"], record["rule_id"]) == ("deny", rule), record
