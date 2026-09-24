"""GLS-SD-010-EMB r10: the generated escape matrix (T9 RULING 13).

The cases are not written here. `sd010_escape_grammar` lists every escape the
three grammars have, checks each against the real decoders, and derives every
expected verdict from the parity contract stated there. This file holds the
table to the decoders and the rule to the table.
"""
import copy
import pathlib
import sys
from collections import Counter

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses.engine import SunglassesEngine          # noqa: E402
from sunglasses.patterns import PATTERNS                # noqa: E402
import sd010_escape_grammar as grammar                  # noqa: E402

RULE = "GLS-SD-010-EMB"
CHANNELS = ["message", "file", "code", "api_response", "log_memory", "agent_input",
            "tool_output", "web_content"]
CASES = grammar.cases()


def _rule():
    return copy.deepcopy(next(p for p in PATTERNS if p["id"] == RULE))


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine(patterns=[_rule()])


def _blocks(engine, text, channel="file"):
    data = engine.scan(text, channel=channel).to_dict()
    return RULE in {f["id"] for f in data.get("findings") or []}


def _mismatches(engine, cases, channel="file"):
    return [(c.name, "expect block" if c.expect_block else "expect allow")
            for c in cases if _blocks(engine, c.text, channel) != c.expect_block]


# ── the table is the grammar ────────────────────────────────────────────────

def test_every_spelling_decodes_as_the_table_says_in_every_grammar_it_names():
    assert grammar.self_check() == []


def test_the_self_check_can_fail():
    """A control: one planted wrong row must be reported."""
    planted = grammar.Escape("\\n", "\t", frozenset({"json"}))
    grammar.TABLE.append(planted)
    try:
        assert grammar.self_check() == [("\\n", "json", "\t", "\n")]
    finally:
        grammar.TABLE.remove(planted)


def test_the_line_ends_are_exactly_what_splitlines_breaks_on():
    breaks = {chr(c) for c in range(0x110000) if len(("a" + chr(c) + "b").splitlines()) == 2}
    assert set(grammar.LINE_ENDS) == breaks - {"\r\n"}


def test_the_table_covers_every_character_the_literal_rule_gives_a_meaning_to():
    decoded = {e.decoded for e in grammar.TABLE}
    meaningful = set(grammar.LINE_ENDS + grammar.DELIMS + grammar.INDENT
                     + grammar.WHITESPACE + "=")
    assert meaningful <= decoded
    families = Counter(e.spelling[:2] for e in grammar.TABLE)
    for prefix in ("\\x", "\\u", "\\U", "\\N", "\\0", "\\1"):
        assert families[prefix], prefix


def test_the_matrix_has_both_verdicts_in_every_position():
    for position in grammar.POSITIONS:
        verdicts = {c.expect_block for c in CASES if c.position == position}
        assert verdicts == {True, False}, position
    assert not any(c.expect_block for c in CASES if c.key != c.key.upper())


# ── the rule is the table ───────────────────────────────────────────────────

@pytest.mark.parametrize("position", sorted(grammar.POSITIONS))
def test_the_rule_matches_the_parity_contract(engine, position):
    wrong = _mismatches(engine, [c for c in CASES if c.position == position])
    assert wrong == [], f"{len(wrong)} disagree; first: {wrong[:25]}"


@pytest.mark.parametrize("channel", CHANNELS)
def test_every_declared_channel_reads_the_same_verdicts(engine, channel):
    sample = CASES[::37]
    assert _mismatches(engine, sample, channel) == []
