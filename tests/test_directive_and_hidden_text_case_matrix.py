"""A wide case matrix for the four rules the directive detection change touches.

Every case in the fixture file is scanned on every channel the engine accepts, and the set of those four rules that fire on each
channel is compared with the set written down for it, so a channel is never left out by omission. The cases cover hidden text in many markups, tags that look empty,
tag names that only start like an exception, font loaders with and without a second handler, ordinary documentation that
names AI models, and orders to put a marker in a reply. Text in the fixture is data only.
"""
import json
import pathlib

import pytest

from sunglasses.engine import SunglassesEngine

RULES = {"GLS-IP-007", "GLS-IP-008", "GLS-HI-002", "GLS-SEM-UI-219"}
CHANNELS = ("message", "file", "api_response", "web_content", "log_memory", "tool_output", "agent_input", "code", "prompt")
CASES = json.loads((pathlib.Path(__file__).parent / "fixtures" / "directive_and_hidden_text_case_matrix.json").read_text())


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def test_the_matrix_channel_list_is_every_channel_the_engine_accepts():
    assert set(CHANNELS) == set(SunglassesEngine.DOCUMENTED_CHANNELS)
    assert all(set(c["expect"]) == set(CHANNELS) for c in CASES)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_each_case_fires_exactly_the_rules_written_down_for_it(engine, case):
    for channel in CHANNELS:
        found = {f["id"] for f in engine.scan(case["text"], channel=channel).findings} & RULES
        assert sorted(found) == case["expect"][channel], (case["kind"], channel)


@pytest.mark.parametrize("rule", sorted(RULES))
def test_the_matrix_holds_cases_that_fire_each_rule_and_cases_that_do_not(rule):
    fires = sum(1 for c in CASES if rule in c["expect"]["web_content"])
    quiet = sum(1 for c in CASES if rule not in c["expect"]["web_content"])
    assert fires >= 1 and quiet >= 1


def test_the_hidden_text_rule_reads_web_content_and_files_and_not_a_plain_message():
    hidden = [c for c in CASES if "GLS-HI-002" in c["expect"]["web_content"]]
    assert hidden
    assert all("GLS-HI-002" in c["expect"]["file"] and "GLS-HI-002" not in c["expect"]["message"] for c in hidden)
