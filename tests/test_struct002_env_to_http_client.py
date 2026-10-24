"""
test_struct002_env_to_http_client.py -- GLS-STRUCT-002: Python or Node code that hands the
whole process environment to an HTTP client is judged by reading the call and its argument,
not by matching characters.

Whether an environment dump is sent depends on structure a text pattern cannot see: where a
call's argument list ends (a comment or a bracket inside a string does not end it), which
argument carries the data, whether the environment is what is sent or only something a
selection was taken from, and whether the host is the local machine. The structural layer
reads a token stream with comments and string bodies masked.

This gate pins:

  1. BLOCK   -- the whole environment inside a client call's data argument, on all five
                channels, including calls that span lines, carry a comment or a bracket in
                a string before the environment, or wrap the environment in a known copy.
  2. CLEAR   -- a selection, a keys-only view, a local-machine literal host, a mocked call,
                text after the call has closed, comments and strings: all clear on every
                channel, from the same builder shapes as the positives.
  3. NOTICE  -- the same call inside a real code fence of a prose text is a notice, never a
                block. The `code` channel is judged as code.
  4. LIMITS  -- shapes this validator does not read (a variable receiver, an alias) are
                pinned as not found, so a change that starts reading them is deliberate.
  5. MUTANTS -- one edit to a positive (select one variable, replace the client) must turn
                it clear.
  6. PLUMBING -- the layer can be switched off; pattern findings and counts are unchanged.
"""
import json
import os

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

RULE = "GLS-STRUCT-002"
CHANNELS = ["code", "message", "file", "tool_output", "web_content"]
PROSE_CHANNELS = [c for c in CHANNELS if c != "code"]
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "env_to_http_client", "samples.json")

with open(FIXTURES, encoding="utf-8") as handle:
    SAMPLES = json.load(handle)


def of(expect):
    return [s for s in SAMPLES if s["expect"] == expect]


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine(PATTERNS)


def found(engine, text, channel):
    return [f for f in engine.scan(text, channel=channel).findings if f["id"] == RULE]


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("sample", of("BLOCK"), ids=lambda s: s["label"])
def test_the_whole_environment_in_a_client_call_blocks_on_every_channel(engine, sample, channel):
    result = engine.scan(sample["text"], channel=channel)
    assert RULE in {f["id"] for f in result.findings}, (sample["label"], channel)
    assert result.decision == "block", (sample["label"], channel)


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("sample", of("CLEAR"), ids=lambda s: s["label"])
def test_selections_local_hosts_mocks_and_text_after_the_call_stay_clear(engine, sample, channel):
    assert not found(engine, sample["text"], channel), (sample["label"], channel)


@pytest.mark.parametrize("channel", PROSE_CHANNELS)
@pytest.mark.parametrize("sample", of("NOTICE"), ids=lambda s: s["label"])
def test_a_call_shown_in_a_code_fence_of_prose_is_a_notice_never_a_block(engine, sample, channel):
    result = engine.scan(sample["text"], channel=channel)
    hits = [f for f in result.findings if f["id"] == RULE]
    assert hits, (sample["label"], channel)
    assert {f["severity"] for f in hits} == {"low"}, (sample["label"], channel)


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("sample", of("MISS"), ids=lambda s: s["label"])
def test_shapes_this_validator_does_not_read_are_pinned_as_not_found(engine, sample, channel):
    """Variable receivers (`session.post`, `client.put`, `s.post`) are out of scope: the
    receiver is a name, and where it was built is not resolved. Not a claim of safety."""
    assert not found(engine, sample["text"], channel), (sample["label"], channel)


def _mutants(text):
    """One edit each; every one must turn a positive clear."""
    out = {}
    for needle, name in (("dict(os.environ", "select"), ("os.environ.copy()", "select"),
                         ("{**os.environ", "select"), ("process.env", "select"),
                         ("json=os.environ", "select")):
        if needle in text:
            replacement = {"dict(os.environ": 'dict(os.environ["K"]',
                           "os.environ.copy()": 'os.environ["K"]',
                           "{**os.environ": '{"K": os.environ["K"]',
                           "process.env": 'process.env["K"]',
                           "json=os.environ": 'json=os.environ["K"]'}[needle]
            out["select_one_variable"] = text.replace(needle, replacement, 1)
            break
    for client in ("requests.post(", "requests.put(", "httpx.post(", "axios.post(", "fetch("):
        if client in text:
            out["not_a_client"] = text.replace(client, "logger.info(", 1)
            break
    return out


BLOCK_MUTANTS = [(s["label"], name, mutated)
                 for s in of("BLOCK") for name, mutated in _mutants(s["text"]).items()]


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("label,name,mutated", BLOCK_MUTANTS, ids=lambda v: v if isinstance(v, str) and len(v) < 40 else "m")
def test_one_edit_to_a_positive_turns_it_clear(engine, label, name, mutated, channel):
    assert not found(engine, mutated, channel), (label, name, channel)


def test_the_mutants_cover_most_of_the_positives():
    assert len(BLOCK_MUTANTS) >= len(of("BLOCK")), "every positive needs at least one mutant"


def test_the_layer_can_be_switched_off_and_the_pattern_count_does_not_move(engine):
    text = of("BLOCK")[0]["text"]
    off = SunglassesEngine(PATTERNS, validators=False)
    assert RULE not in {f["id"] for f in off.scan(text, channel="file").findings}
    assert RULE in {f["id"] for f in engine.scan(text, channel="file").findings}


def test_the_validator_is_registered_with_its_own_id():
    from sunglasses import validators
    ids = [v.id for v in validators.VALIDATORS]
    assert RULE in ids and len(ids) == len(set(ids))
