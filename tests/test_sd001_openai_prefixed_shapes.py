"""GLS-SD-001 and its -API sibling: OpenAI project, service-account and admin key shapes.

OpenAI's own client code treats four prefixes as OpenAI keys: `sk-proj-`, `sk-svcacct-`, `sk-admin-`
and plain `sk-`. Only the prefixes are vendor-confirmed; the length and the body alphabet are not
documented anywhere this repository can read. So the rule asks for the three prefixes, then twenty
or more letters, digits, underscores or hyphens, and the twenty is a floor chosen to keep short
prose out, not a claim about key length.

The left boundary from `test_sd001_left_boundary.py` applies here for the same reason, and it is not
optional: without it `risk-proj-...`, `disk-admin-...` and `task-svcacct-...` are ordinary words.

THE COST, PINNED RATHER THAN HIDDEN. A key written directly after a letter or digit is not reported
by this alternative, and prose that begins a token with one of the three prefixes and runs twenty
characters or more is reported.

NOT ONE CREDENTIAL-SHAPED LITERAL IS STORED HERE; values are assembled from fragments.
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
_PREFIXES = ["sk" + "-proj-", "sk" + "-svcacct-", "sk" + "-admin-"]
_PLAIN = rows._fill(rows._LOWER, 40)
_MIXED = rows._fill(rows._LOWER, 18) + "_" + rows._fill(rows._LOWER, 14) + "-" + rows._fill(rows._LOWER, 20)
_RULE_CHANNEL = {"GLS-SD-001": "file", "GLS-SD-001-API": "api_response"}
_CHANNELS = ["message", "file", "api_response", "web_content", "log_memory", "tool_output",
             "agent_input", "code", "prompt"]


def _alone(rule_id):
    return SunglassesEngine(patterns=[_BY_ID[rule_id]], mechanisms=False)


def _hits(rule_id, text):
    return [f["id"] for f in _alone(rule_id).scan(text, _RULE_CHANNEL[rule_id]).findings]


def _declared(rule_id):
    return sorted(_BY_ID[rule_id]["channel"])


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("prefix", _PREFIXES)
@pytest.mark.parametrize("body", [_PLAIN, _MIXED], ids=["alnum", "underscore-and-hyphen"])
@pytest.mark.parametrize("before", ["", "=", ":", " ", '"', "'", "(", "[", "\n", "`", "KEY=", "Bearer ",
                                    '"api_key": "', "export K=", "KEY_"])
def test_a_prefixed_key_at_a_word_edge_fires(rule_id, prefix, body, before):
    assert rule_id in _hits(rule_id, before + prefix + body + " end")


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("word,prefix", [("risk", "proj-"), ("disk", "admin-"), ("task", "svcacct-"),
                                         ("desk", "proj-"), ("mask", "admin-"), ("TASK", "svcacct-")])
def test_a_word_ending_in_sk_is_not_a_key(rule_id, word, prefix):
    assert _hits(rule_id, f"see {word}-{prefix}{_PLAIN} ok") == []


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("text", [
    "sk" + "-admin-1234abcd",                       # a documentation placeholder, shorter than the floor
    "sk" + "-admin-panel",
    "sk" + "-proj-",
    "sk" + "-svcacct-short",
    "sk" + "-abcdefghijklmnop123",                  # a documentation placeholder, 19 characters
], ids=["admin-placeholder", "admin-panel", "bare-prefix", "svcacct-short", "plain-placeholder"])
def test_placeholders_and_short_strings_stay_clean(rule_id, text):
    assert _hits(rule_id, f"example: {text} end") == []


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("prefix", _PREFIXES)
def test_a_key_glued_to_a_letter_is_the_disclosed_cost(rule_id, prefix):
    """Pinned in the direction that is NOT a feature, so the cost cannot drift unnoticed."""
    assert _hits(rule_id, "x" + prefix + _PLAIN) == []
    assert _hits(rule_id, "7" + prefix + _PLAIN) == []


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
def test_the_hazard_row_is_known_prose_that_starts_a_token_with_the_prefix(rule_id):
    """Documented, not hidden: a token that STARTS with the prefix and runs 20+ characters fires."""
    prose = "sk" + "-admin-configuration-and-management-guide"
    assert rule_id in _hits(rule_id, f"read {prose} first")


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
def test_the_plain_and_anthropic_shapes_are_unchanged(rule_id):
    assert rule_id in _hits(rule_id, "k=" + "sk" + "-" + _PLAIN)
    assert rule_id in _hits(rule_id, "k=" + "sk" + "-ant-" + rows._fill(rows._LOWER, 24))


def test_the_sibling_carries_the_same_alternatives_as_the_parent():
    assert _BY_ID["GLS-SD-001"]["regex"] == _BY_ID["GLS-SD-001-API"]["regex"]


@pytest.mark.parametrize("prefix", _PREFIXES)
@pytest.mark.parametrize("channel", _CHANNELS)
def test_the_full_ruleset_decides_a_prefixed_key_like_a_plain_one(prefix, channel):
    """On every channel, including the aliases and the ones neither rule declares, the three new
    shapes get the decision and the SD findings the plain shape already gets. Nothing gains a
    channel, nothing loses one."""
    engine = SunglassesEngine()

    def verdict(secret):
        r = engine.scan("k=" + secret, channel)
        return r.decision, sorted(f["id"] for f in r.findings if f["id"].startswith("GLS-SD-001"))

    assert verdict(prefix + _PLAIN) == verdict("sk" + "-" + _PLAIN)


def test_the_new_shapes_block_where_the_rules_are_declared():
    for channel in ("message", "file", "api_response", "log_memory", "agent_input", "tool_output"):
        for prefix in _PREFIXES:
            assert SunglassesEngine().scan("k=" + prefix + _PLAIN, channel).decision == "block", (prefix, channel)


@pytest.mark.parametrize("channel", _CHANNELS)
def test_the_full_ruleset_stays_clean_on_a_word_internal_id(channel):
    result = SunglassesEngine().scan("created task-proj-" + _PLAIN + " ok", channel)
    assert not [f["id"] for f in result.findings if f["id"].startswith("GLS-SD-")]
