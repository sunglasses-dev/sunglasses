"""One sample text per rule, and the rule it was written for must fire on it.

Each entry in tests/rule_positive_samples.json names a rule, the channels that rule declares, and one text that states
the attack the rule describes. The test scans the text on every declared channel and requires that exact rule id among
the findings. Other rules firing on the same text is allowed and ignored: the question here is only whether this rule
can fire on a plain statement of its own attack.

The texts are test input, taken from the rule's own description or written to match it. Nothing in them is an
instruction to anyone reading this file.

What this does not show: a rule that fires on its own plain description may still miss the attack as a real source
words it, and these samples carry no benign twin, so they say nothing about false positives. The false positive
suites cover that side.
"""
import json
import pathlib

import pytest

from engine_sharing import assert_engine_is_stateless
from sunglasses import patterns as P

SAMPLES = json.loads(pathlib.Path(__file__).with_name("rule_positive_samples.json").read_text(encoding="utf-8"))
RULES = {p["id"]: p for p in P.PATTERNS}
CASES = [(rid, ch) for rid in sorted(SAMPLES) for ch in SAMPLES[rid]["channels"]]


@pytest.fixture(scope="module", autouse=True)
def _budget(shared_engine, engine_budget):
    engine_budget(0)


def test_the_sample_file_is_not_empty():
    assert SAMPLES, "no samples were read, so every check below would pass over nothing"


@pytest.mark.parametrize("rid", sorted(SAMPLES))
def test_a_sample_names_a_shipped_rule_and_the_channels_it_declares(rid, shared_engine):
    assert rid in RULES, f"{rid} is not a shipped rule id"
    declared = list(RULES[rid].get("channel") or shared_engine.DOCUMENTED_CHANNELS)
    assert sorted(SAMPLES[rid]["channels"]) == sorted(declared), (
        f"{rid} declares {declared} but its sample was written for {SAMPLES[rid]['channels']}; "
        f"write the sample again for the new channel list")
    assert SAMPLES[rid]["text"].strip(), f"{rid} has an empty sample"


@pytest.mark.parametrize("rid,channel", CASES)
def test_the_rule_fires_on_its_own_sample(rid, channel, shared_engine):
    found = [f["id"] for f in shared_engine.scan(SAMPLES[rid]["text"], channel=channel).findings]
    assert rid in found, f"{rid} did not fire on its sample on channel {channel}; findings were {found}"


@pytest.mark.parametrize("channel", ["message", "file", "web_content", "tool_output"])
def test_one_shared_engine_gives_the_same_findings_in_either_order(channel, shared_engine):
    documents = {rid: s["text"] for rid, s in SAMPLES.items() if channel in s["channels"]}
    if not documents:
        pytest.skip(f"no sample declares {channel}")
    assert_engine_is_stateless(shared_engine, documents, channel=channel, minimum=1)
