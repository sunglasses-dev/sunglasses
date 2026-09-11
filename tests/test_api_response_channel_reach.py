"""STATE #39, part one: the `api_response` channel could not see indirect
instruction attacks that the same engine caught on `tool_output`.

An agent reading a tool's reply and an agent reading an HTTP API's reply are in
the same position: both are consuming text produced by something that is not the
user, and both can be steered by instructions hidden in it. Six indirect
instruction rules listed `tool_output` and omitted `api_response`, so the same
payload was a finding through one door and silent through the other.

Reproduced independently before the fix (2026-09-10): five of the six stored
fixtures produced findings under `tool_output` and NOTHING under `api_response`.

This is deliberately a channel-reach fix and nothing more. It adds one channel
to six existing rules. It does not remove channel filtering, it does not add a
pattern, and it makes no claim that anything intercepts MCP traffic.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses.engine import SunglassesEngine   # noqa: E402


FIXTURES = pathlib.Path(
    __file__).resolve().parents[1] / "tests" / "fixtures" / "api_response_reach"

# The six rules whose channel list omitted `api_response`.
RULES = ["GLS-PI-013", "GLS-PI-016", "GLS-PI-017",
         "GLS-PI-021", "GLS-PI-INFO", "GLS-PIEMN-001"]

# The five fixtures that fired on `tool_output` and were clean on
# `api_response`. `policy_override_prompt_exfil` is excluded from this list on
# purpose: it already produced a finding on `api_response` through a different
# rule, so it cannot demonstrate the gap. It appears below as a control that the
# fix does not disturb what already worked.
GAP_CASES = [
    ("agentdojo_information_wrapper", "GLS-PI-INFO"),
    ("malicious_readme_agent_targeting", "GLS-PI-013"),
    ("typoglycemic_redaction_override", "GLS-PI-017"),
    ("authority_impersonation", "GLS-PI-021"),
    ("hidden_comment_agent_instruction", "GLS-PIEMN-001"),
]

# Ordinary API-shaped text an agent reads all day. None of it may become a
# threat because six rules gained a channel.
BENIGN = {
    "json_api_response":
        '{"status":"ok","data":{"id":42,"name":"widget"},"took_ms":13}',
    "ci_build_log":
        "build 1841 passed\n  14 tests, 0 failures\n  artifacts uploaded\n",
    "config_yaml":
        "service:\n  port: 8080\n  retries: 3\n  timeout_seconds: 30\n",
    "support_ticket":
        "Customer reports the export button does nothing on Safari 17. "
        "Asked them to send a console log. Reproduced on staging.",
    "changelog":
        "## 2.1.0\n- faster pagination\n- fixed a crash when the cache was cold\n",
    "readme_install":
        "## Install\n\n    pip install widget\n\nThen run `widget --help`.",
}


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _ids(result):
    findings = result.findings if hasattr(result, "findings") else result
    return {f["id"] for f in findings}


@pytest.mark.parametrize("case,rule", GAP_CASES, ids=[c[0] for c in GAP_CASES])
def test_an_api_reply_is_inspected_like_a_tool_reply(engine, case, rule):
    """The gap itself. Fails before the fix, on every one of the five."""
    text = (FIXTURES / f"{case}.txt").read_text()
    assert rule in _ids(engine.scan(text, channel="tool_output")), (
        f"premise changed: {rule} no longer fires on tool_output for {case}"
    )
    assert rule in _ids(engine.scan(text, channel="api_response")), (
        f"{case}: {rule} sees this payload through tool_output and is blind to "
        "it through api_response. Same text, same agent, different door."
    )


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_ordinary_api_text_stays_clean(engine, name):
    """The other half: reach must not be bought with false positives."""
    assert not _ids(engine.scan(BENIGN[name], channel="api_response")), (
        f"{name}: ordinary API-shaped text became a threat on api_response"
    )


def test_the_already_detected_case_is_undisturbed(engine):
    """`policy_override_prompt_exfil` already fired on api_response.

    It is the control for "the fix did not change what already worked", which
    is why it is not counted among the five.
    """
    text = (FIXTURES / "policy_override_prompt_exfil.txt").read_text()
    assert _ids(engine.scan(text, channel="api_response")), (
        "a finding that existed on api_response before the change disappeared"
    )


def test_every_touched_rule_still_covers_the_channels_it_had():
    """Adding a channel must never remove one. Compared against frozen evidence.

    The first version of this test ended in `or True`, which made it vacuous:
    an external reviewer disabled a rule's bindings and all 14 tests stayed
    green. Its follow-up loop also walked file, web_content and tool_output and
    silently omitted `message`, so removing five `message` bindings changed
    nothing visible either.

    The repair is to stop restating the change and start comparing it to
    evidence. `channels_before.json` is the channel set of each rule read
    straight from origin/main before this branch touched it, so the expected
    value is exactly baseline plus `api_response` and nothing else moves.
    """
    import json
    before = json.loads((FIXTURES / "channels_before.json").read_text())
    engine = SunglassesEngine()
    by_id = {p["id"]: p for p in engine._patterns}

    assert sorted(before) == sorted(RULES), (
        "the frozen baseline no longer covers exactly the rules this branch "
        "touches -- refreeze it deliberately rather than editing this list"
    )

    for rule in RULES:
        assert rule in by_id, f"{rule} not found in the pattern set"
        now = set(by_id[rule].get("channel", ()))
        expected = set(before[rule]) | {"api_response"}
        assert now == expected, (
            f"{rule}: channels are {sorted(now)}, expected {sorted(expected)}. "
            f"Baseline was {sorted(before[rule])}; this branch may add "
            "api_response and change nothing else."
        )


def test_the_change_is_channel_reach_and_not_new_patterns(engine):
    """Guard against the fix quietly becoming something larger."""
    for rule in RULES:
        matches = [p for p in engine._patterns if p["id"] == rule]
        assert len(matches) == 1, f"{rule} is declared {len(matches)} times"
