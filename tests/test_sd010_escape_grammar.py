"""GLS-SD-010-EMB r10: the generated escape matrix (T9 RULING 13).

The cases are not written here. `sd010_escape_grammar` lists every escape the
three grammars have, checks each against the real decoders, and derives every
expected verdict from the parity contract stated there. This file holds the
table to the decoders and the rule to the table.
"""
import copy
import pathlib
import sys
import unicodedata
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


# ── the matrix reaches every family a reviewer has probed ───────────────────
# R32. Round 10's reviewer probed four families the r10 matrix never generated,
# and one of them (non-ASCII letters inside a character name) was a false
# positive 37 green tests and 17 dead mutations could not see. This is the red:
# every escape round 10 put beside a key, classified by the same function as
# every matrix spelling, must name a family the matrix has. The classifier is
# written HERE, independent of sd010_escape_grammar, so it can be pointed at an
# older matrix and show what that matrix lacked.

def _family(spelling):
    intro, rest = spelling[1:2], spelling[2:]
    if intro in "Nn" and rest.startswith("{"):
        if not rest.isascii():
            return "named, non-ASCII letter in the name"
        return "named" if intro == "N" else "named, lower-case introducer"
    if intro == "x":
        return "hex"
    if intro == "X":
        return "hex, upper-case introducer"
    if intro == "u":
        return "\\u, four digits" if len(rest) == 4 else "\\u, other length"
    if intro == "U":
        return "\\U, eight digits" if len(rest) == 8 else "\\U, other length"
    if intro.isdigit():
        return "octal"
    return "one character"


R10_PROBES = {   # verbatim from SD010EMB_e2942a5_r10_VERDICT.md
    "r10_ascii_named_indent_control": "\\N{SPACE}",
    "r10_ascii_named_boundary_control": "\\N{LINE FEED}",
    "r10_long_s_lowername_control": "\\N{\u017fPACE}",
    "r10_dotted_i_lowername_control": "\\N{L\u0130NE FEED}",
    "r10_dotless_i_named_boundary": "\\N{L\u0131NE FEED}",
    "r10_long_s_named_line_separator": "\\N{LINE \u017fEPARATOR}",
    "r10_invalid_dotted_i_named_boundary": "\\N{L\u0130NE FEED}",
    "r10_invalid_long_s_named_indent": "\\N{\u017fPACE}",
    "r10_invalid_upper_X_boundary": "\\X0a",
    "r10_invalid_upper_X_indent": "\\X20",
    "r10_invalid_short_upper_U_boundary": "\\U000a",
    "r10_lower_n_named_indent": "\\n{SPACE}",
    "r10_lower_n_named_boundary": "\\n{LINE FEED}",
    "r10_upper_X_separator": "\\X20",
    "r10_lower_x_boundary_control": "\\x0a",
    "r10_upper_U_full_boundary_control": "\\U0000000a",
}


def test_the_matrix_has_every_family_round_10_probed():
    have = {_family(c.spelling) for c in CASES}
    missing = {name: _family(s) for name, s in R10_PROBES.items() if _family(s) not in have}
    assert missing == {}


def test_every_round_10_probe_spelling_is_in_the_matrix():
    spelled = {c.spelling for c in CASES}
    assert sorted(n for n, s in R10_PROBES.items() if s not in spelled) == []


def test_a_name_folds_ascii_only_in_the_decoder():
    """The premise of the name family, asked of the decoder and not assumed:
    ASCII case is free, a non-ASCII equivalent is refused."""
    assert grammar.FOLD_EQUIVALENTS, "the regex engine folds no non-ASCII letter to ASCII"
    assert grammar.decode("python", "\\N{Line Feed}") == "\n"
    for fold, letters in grammar.FOLD_EQUIVALENTS.items():
        name = unicodedata.name(letters[-1])            # LATIN CAPITAL LETTER <it>
        assert grammar.decode("python", "\\N{%s}" % name) == letters[-1]
        with pytest.raises(SyntaxError):
            grammar.decode("python", "\\N{%s}" % (name[:-1] + fold))


# ── the rule is the table ───────────────────────────────────────────────────

@pytest.mark.parametrize("position", sorted(grammar.POSITIONS))
def test_the_rule_matches_the_parity_contract(engine, position):
    wrong = _mismatches(engine, [c for c in CASES if c.position == position])
    assert wrong == [], f"{len(wrong)} disagree; first: {wrong[:25]}"


@pytest.mark.parametrize("channel", CHANNELS)
def test_every_declared_channel_reads_the_same_verdicts(engine, channel):
    sample = CASES[::37]
    assert _mismatches(engine, sample, channel) == []


# ── every fragment is load-bearing, proven by removing it ───────────────────
# (name, the bytes removed or narrowed, what replaces them, the direction the
# matrix must fail in). Each mutant is the rule with ONE family taken out; the
# matrix has to see it. `count == 1` is asserted so a moved fragment fails
# here instead of silently mutating nothing.
MUTATIONS = [
    ("boundary one-char", r"(?-i:\\[nrvfNLP]", r"(?-i:\\[rvfNLP]", "miss"),
    ("boundary hex", r"|\\x(?:0[a-dA-D]|1[c-eC-E]|85|2[27cC]|5[bB]|7[bB])", "", "miss"),
    ("boundary \\u", r"|\\u(?:00(?:0[a-dA-D]|1[c-eC-E]|85|2[27cC]|5[bB]|7[bB])|202[89])",
     "", "miss"),
    ("boundary \\U", r"|\\U0000(?:00(?:0[a-dA-D]|1[c-eC-E]|85|2[27cC]|5[bB]|7[bB])|202[89])",
     "", "miss"),
    ("boundary octal", r"|\\(?:0?(?:1[2-5]|3[4-6]|4[27]|54)|205|133|173)", "", "miss"),
    ("boundary names", r"\{(?ai:LINE FEED|", r"\{(?ai:", "miss"),
    ("boundary literal line ends", r"\v\f\x1c-\x1e\x85", "", "miss"),
    ("indentation one-char", r"\\[ \tt]", r"\\[t]", "miss"),
    ("indentation numeric", r"|\\x(?:09|20)|\\u00(?:09|20)|\\U000000(?:09|20)", "", "miss"),
    ("indentation octal", r"|\\0?(?:11|40)", "", "miss"),
    ("indentation names", r"(?ai:SPACE|SP|CHARACTER TABULATION|HORIZONTAL TABULATION|TAB|HT)",
     r"(?ai:SPACE)", "miss"),
    ("separator hex", r"|\\x(?:0[9a-dA-D]|1[c-fC-F]|20|85|[aA]0)", "", "miss"),
    ("separator \\u", r"|\\u(?:00(?:0[9a-dA-D]|1[c-fC-F]|20|85|[aA]0)|1680|200[0-9aA]",
     r"|\\u(?:00(?:0[9a-dA-D]|1[c-fC-F]|20|85|[aA]0)|200[0-9aA]", "miss"),
    ("separator octal", r"|\\(?:0?(?:1[1-5]|3[4-7]|40)|205|240)", "", "miss"),
    ("separator names", r"|NBSP|NO-BREAK SPACE|", "|NBSP|", "miss"),
    ("equals", r"|\\u003[dD]", "", "miss"),
    # The over-fire direction: the r9 separator read a backslash before ANY
    # whitespace as an escape, and IGNORECASE read \R \T \V as escapes.
    ("separator any backslash-space", r"\\[ \t\n\r\x85\u2028\u2029tnrfvNLP_]",
     r"\\[\stnrfvNLP_]", "over"),
    ("escapes case-folded", "(?-i:\\\\", "(?:\\\\", "over"),
    ("a lazy space name", "|NBSP|NO-BREAK SPACE|", "|NBSP|[A-Z -]*SPACE|", "over"),
    # r10: a name matched under Unicode folding read L\u0130NE FEED as LINE FEED.
    ("names fold beyond ASCII", "(?ai:", "(?i:", "over"),
]
# Mutations that replace EVERY occurrence, and the least count they need.
_EVERYWHERE = {"escapes case-folded": 4, "names fold beyond ASCII": 4}


@pytest.mark.parametrize("name,old,new,direction", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_control_each_fragment_is_seen_by_the_matrix(name, old, new, direction):
    rule = _rule()
    regex = rule["regex"][0]
    if name in _EVERYWHERE:
        assert regex.count(old) >= _EVERYWHERE[name], (name, regex.count(old))
        mutated = regex.replace(old, new)
    else:
        assert regex.count(old) == 1, (name, regex.count(old))
        mutated = regex.replace(old, new, 1)
    rule["regex"] = [mutated]
    wrong = _mismatches(SunglassesEngine(patterns=[rule]), CASES)
    want = "expect block" if direction == "miss" else "expect allow"
    assert [w for w in wrong if w[1] == want], f"{name}: the matrix did not see it"
