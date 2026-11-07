"""GLS-SD-001 and its -API sibling: an OpenAI or Anthropic key shape is a key only at a word edge.

`sk-` followed by twenty letters or digits matched INSIDE words: `task-`, `disk-`, `risk-`, `desk-`
and any other word ending in `sk` followed by a long id (a task id, a volume id). Tool results and
logs are full of those, and every one blocked. The two shapes now require that the character before
`sk-` is not a letter or digit.

THE COST, PINNED RATHER THAN HIDDEN. A key written directly after a letter or digit (`xsk-...`) is
no longer reported by these two alternatives. A real key sits after `=`, `:`, a quote, a space, a
bracket or a line start, and each of those is pinned below. The other credential rules are not
changed by this file.

NOT ONE CREDENTIAL-SHAPED LITERAL IS STORED HERE; values are assembled from the fragments in
`sd_api_sibling_rows`.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses.engine import SunglassesEngine          # noqa: E402
from sunglasses.patterns import PATTERNS                 # noqa: E402
import sd_api_sibling_rows as rows                       # noqa: E402

_BY_ID = {p["id"]: p for p in PATTERNS}
_OPENAI = rows._OPENAI + rows._fill(rows._LOWER, 32)
_ANTHROPIC = "sk" + "-ant-" + rows._fill(rows._LOWER, 24)
_ID = rows._fill(rows._LOWER, 24)

_RULE_CHANNEL = {"GLS-SD-001": "file", "GLS-SD-001-API": "api_response"}


def _alone(rule_id):
    """An engine carrying only this rule, so a finding can only have come from it."""
    return SunglassesEngine(patterns=[_BY_ID[rule_id]], mechanisms=False)


def _hits(rule_id, text):
    result = _alone(rule_id).scan(text, _RULE_CHANNEL[rule_id])
    return [f["id"] for f in result.findings]


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("word", ["task", "disk", "risk", "desk", "mask", "flask", "TASK", "Task"])
def test_an_id_inside_a_word_is_not_a_key(rule_id, word):
    assert _hits(rule_id, f"created {word}-{_ID} ok") == []


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("secret", [_OPENAI, _ANTHROPIC], ids=["openai", "anthropic"])
@pytest.mark.parametrize("before", ["", "=", ":", " ", '"', "'", "(", "[", "\n", "\t", "`", ",", "/",
                                    "KEY=", "Bearer ", '"api_key": "', "export K="])
def test_a_key_at_a_word_edge_still_fires(rule_id, secret, before):
    assert rule_id in _hits(rule_id, before + secret + " end")


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
def test_a_key_glued_to_a_letter_is_the_disclosed_cost(rule_id):
    """Pinned in the direction that is NOT a feature, so the cost cannot drift unnoticed."""
    assert _hits(rule_id, "x" + _OPENAI) == []
    assert _hits(rule_id, "7" + _ANTHROPIC) == []


def test_the_sibling_carries_the_same_two_alternatives_as_the_parent():
    assert _BY_ID["GLS-SD-001"]["regex"] == _BY_ID["GLS-SD-001-API"]["regex"]


@pytest.mark.parametrize("channel", ["message", "file", "api_response", "web_content", "log_memory", "tool_output", "agent_input", "code", "prompt"])
def test_the_full_ruleset_agrees_on_a_word_internal_id(channel):
    engine = SunglassesEngine()
    result = engine.scan(f"created task-{_ID} ok", channel)
    assert not [f["id"] for f in result.findings if f["id"].startswith("GLS-SD-")]
