"""What stands in front of an OpenAI style or Anthropic style key, for the API key rule and the rule that holds the doubtful case.

An OpenAI style key is the letters sk, a hyphen and twenty letters or digits. That also matches inside words such
as task, disk, risk and desk followed by a long id (a task id, a volume id). Tool results and logs are full of
those, so a letter in front cannot carry the full severity.

One row per character in front.
  * The Anthropic style has no edge test at all, because no word ends in its prefix.
  * The OpenAI style keeps its full severity after anything that is not a letter (a digit, an equals sign, a
    colon, a quote, a space, a bracket, a line start), so a key written after a digit is reported.
  * The OpenAI style directly after a letter is held one level lower by the medium rule pair, so it is
    quarantined instead of blocked, but only when the run holds a capital, a small letter and a digit, as a real
    key does. An id of one class or two, as a hash or a task id is, is not held.

Not one credential shaped literal is stored here. Values are assembled from the fragments in
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
# A run with a capital, a small letter and a digit, as a real key has; and runs that lack one of the three.
_MIXED = "Ab1" + rows._fill(rows._LOWER, 24)
_QUIET_RUNS = {
    "hex24": "0123456789abcdef01234567",
    "hex32": "0123456789abcdef0123456789abcdef",
    "capitals26": rows._fill(rows._UPPER, 26),
    "lower24": _ID,
    "letters_only": "AbCdEfGhIjKlMnOpQrStUvWx",
    "no_small": "AB1CD2EF3GH4IJ5KL6MN7OP8",
    "no_capital": "ab1cd2ef3gh4ij5kl6mn7op8",
}

_FULL = {"GLS-SD-001": "file", "GLS-SD-001-API": "api_response"}
_HELD = {"GLS-SD-011": "file", "GLS-SD-011-API": "api_response"}
_RULE_CHANNEL = {**_FULL, **_HELD}
_PAIRS = [("GLS-SD-001", "GLS-SD-011"), ("GLS-SD-001-API", "GLS-SD-011-API")]


def _alone(rule_id):
    """An engine carrying only this rule, so a finding can only have come from it."""
    return SunglassesEngine(patterns=[_BY_ID[rule_id]], mechanisms=False)


def _hits(rule_id, text):
    result = _alone(rule_id).scan(text, _RULE_CHANNEL[rule_id])
    return [f["id"] for f in result.findings]


_EDGE = ["", "=", ":", " ", '"', "'", "(", "[", "\n", "\t", "`", ",", "/", "7",
         "KEY=", "Bearer ", '"api_key": "', "export K="]


@pytest.mark.parametrize("rule_id", sorted(_FULL))
@pytest.mark.parametrize("before", _EDGE)
@pytest.mark.parametrize("secret", [_OPENAI, _ANTHROPIC], ids=["openai", "anthropic"])
def test_a_key_after_anything_but_a_letter_keeps_its_full_severity(rule_id, secret, before):
    assert rule_id in _hits(rule_id, before + secret + " end")


@pytest.mark.parametrize("rule_id", sorted(_FULL))
@pytest.mark.parametrize("letter", ["x", "k", "Z", "t"])
def test_the_anthropic_shape_after_a_letter_keeps_its_full_severity(rule_id, letter):
    assert rule_id in _hits(rule_id, letter + _ANTHROPIC)


@pytest.mark.parametrize("rule_id", sorted(_FULL))
@pytest.mark.parametrize("word", ["task", "disk", "risk", "desk", "mask", "flask", "TASK", "Task"])
def test_the_openai_shape_after_a_letter_is_not_the_full_severity_rule(rule_id, word):
    assert _hits(rule_id, f"created {word}-{_ID} ok") == []
    assert _hits(rule_id, word + _OPENAI) == []


@pytest.mark.parametrize("rule_id", sorted(_HELD))
@pytest.mark.parametrize("word", ["task", "disk", "risk", "desk", "mask", "flask", "TASK", "Task"])
def test_the_openai_shape_after_a_letter_is_held(rule_id, word):
    assert rule_id in _hits(rule_id, f"created {word}-{_MIXED} ok")
    assert rule_id in _hits(rule_id, word + rows._OPENAI + _MIXED)


@pytest.mark.parametrize("rule_id", sorted(_HELD))
@pytest.mark.parametrize("letter", ["x", "k", "Z", "a"])
def test_one_letter_in_front_of_the_openai_shape_is_held(rule_id, letter):
    assert rule_id in _hits(rule_id, letter + rows._OPENAI + _MIXED)


@pytest.mark.parametrize("rule_id", sorted(_HELD))
@pytest.mark.parametrize("word", ["task", "disk", "risk", "x"])
@pytest.mark.parametrize("run", sorted(_QUIET_RUNS))
def test_a_run_that_lacks_a_class_is_not_held(rule_id, word, run):
    assert _hits(rule_id, f"created {word}{rows._OPENAI}{_QUIET_RUNS[run]} ok") == []


@pytest.mark.parametrize("rule_id", sorted(_HELD))
def test_the_class_test_reads_the_whole_run_not_its_first_characters(rule_id):
    late = _QUIET_RUNS["lower24"] + "A" + "9"
    assert rule_id in _hits(rule_id, "x" + rows._OPENAI + late)


@pytest.mark.parametrize("rule_id", sorted(_FULL))
@pytest.mark.parametrize("letter", ["x", "k", "Z", "a"])
def test_one_letter_in_front_of_the_openai_shape_is_not_the_full_rule(rule_id, letter):
    assert _hits(rule_id, letter + _OPENAI) == []


@pytest.mark.parametrize("rule_id", sorted(_HELD))
@pytest.mark.parametrize("before", [b for b in _EDGE if not b or not b[-1].isalpha()])
def test_the_held_rule_stays_quiet_when_no_letter_stands_in_front(rule_id, before):
    assert _hits(rule_id, before + rows._OPENAI + _MIXED + " end") == []
    assert _hits(rule_id, before + _ANTHROPIC + " end") == []


@pytest.mark.parametrize("held", sorted(_HELD))
def test_the_held_rule_is_one_level_below_the_full_rule(held):
    assert _BY_ID[held]["severity"] == "medium"
    assert _BY_ID[held.replace("011", "001")]["severity"] == "high"


@pytest.mark.parametrize("full,held", _PAIRS)
def test_the_held_rule_has_the_channels_of_its_full_twin(full, held):
    assert _BY_ID[full]["channel"] == _BY_ID[held]["channel"]


def test_the_sibling_carries_the_same_alternatives_as_the_parent():
    assert _BY_ID["GLS-SD-001"]["regex"] == _BY_ID["GLS-SD-001-API"]["regex"]
    assert _BY_ID["GLS-SD-011"]["regex"] == _BY_ID["GLS-SD-011-API"]["regex"]


@pytest.mark.parametrize("channel,expected_rule", [("file", "GLS-SD-011"), ("message", "GLS-SD-011"),
                                                  ("api_response", "GLS-SD-011-API"), ("tool_output", "GLS-SD-011-API"),
                                                  ("code", "GLS-SD-011"), ("prompt", "GLS-SD-011")])
def test_the_full_ruleset_quarantines_a_word_glued_key_run_and_never_blocks_it(channel, expected_rule):
    result = SunglassesEngine().scan(f"created task-{_MIXED} ok", channel)
    sd = {f["id"] for f in result.findings if f["id"].startswith("GLS-SD-")}
    assert expected_rule in sd
    assert not sd & {"GLS-SD-001", "GLS-SD-001-API"}
    assert result.decision == "quarantine"


@pytest.mark.parametrize("channel", ["file", "message", "api_response", "tool_output", "code", "prompt", "log_memory", "agent_input"])
@pytest.mark.parametrize("run", sorted(_QUIET_RUNS))
@pytest.mark.parametrize("word", ["task", "disk", "risk"])
def test_the_full_ruleset_reports_nothing_for_an_id_after_a_word_that_lacks_a_class(channel, run, word):
    result = SunglassesEngine().scan(f"created {word}-{_QUIET_RUNS[run]} ok", channel)
    assert not [f["id"] for f in result.findings if f["id"].startswith("GLS-SD-0")]
    assert result.decision == "allow"


@pytest.mark.parametrize("channel", ["file", "message", "api_response", "tool_output"])
@pytest.mark.parametrize("before", ["=", ":", " ", "7", '"'])
def test_the_full_ruleset_blocks_a_key_after_a_character_that_is_not_a_letter(channel, before):
    result = SunglassesEngine().scan(f"token{before}{_OPENAI}", channel)
    assert result.decision == "block"


@pytest.mark.parametrize("channel", ["file", "message", "api_response", "tool_output"])
def test_the_full_ruleset_blocks_the_anthropic_shape_after_a_letter(channel):
    assert SunglassesEngine().scan("x" + _ANTHROPIC, channel).decision == "block"


@pytest.mark.parametrize("channel", ["web_content"])
def test_a_channel_neither_rule_lists_reads_neither_of_them(channel):
    result = SunglassesEngine().scan(f"created task-{_MIXED} ok", channel)
    assert not [f["id"] for f in result.findings if f["id"].startswith("GLS-SD-0")]
