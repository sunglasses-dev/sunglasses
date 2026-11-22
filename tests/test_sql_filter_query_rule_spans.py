"""The SQL filter query rule (GLS-SI-001) reports the same occurrences, spans and decisions as ORACLE_SOURCE, a frozen
copy of the rule's expression in release 0.6.26 that is not read from the package, so a later edit of the rule cannot
move the oracle with it. The rule's own last regex must give the same match, span for span, at EVERY offset of every
text of the families below, with the key on and with the key off, and the engine must give the same decision. There is
no timing and no long text in this file.
"""
import itertools
import json
import random
import re
from pathlib import Path

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

RULE_ID = "GLS-SI-001"
ENTRY = 5
ORACLE_SOURCE = r"\.format\s*\(.*\)\s*#.*(?:sql|query|select|where)"
ORACLE = re.compile(ORACLE_SOURCE, re.IGNORECASE)
RULE = next(p for p in PATTERNS if p["id"] == RULE_ID)


def _engine(keyed):
    rule = {k: v for k, v in RULE.items() if keyed or k != "start_memo"}
    return SunglassesEngine(patterns=[rule], mechanisms=False)


def _compiled(engine):
    return engine._compiled_by_id[RULE_ID][ENTRY]


def _walk(engine, text):
    mode, rx, key = _compiled(engine)
    out, pos, memo = [], 0, {}
    while (found := engine._eval_regex(mode, rx, key, text, pos, memo)) is not None:
        out.append(found.span())
        pos = found.start() + 1
    return out


def _oracle_walk(text):
    out, pos = [], 0
    while (found := ORACLE.search(text, pos)) is not None:
        out.append(found.span())
        pos = found.start() + 1
    return out


def _every_offset(rx, text):
    return [(s, rx.match(text, s).span() if rx.match(text, s) else None) for s in range(len(text) + 1)]


def _decision(engine, text, channel):
    result = engine.scan(text, channel)
    return result.decision, sorted(f.get("id") for f in result.findings)


FRONTS = ["", "x", "msg = \"{}\"", "q = sql.", "a.b"]
STARTS = [".format(", ".format (", ".format\n(", ".format \n ( ", ".format(\n"]
GAPS = ["", "a", "a, b", "a)", "a) b", "a)b)", "(a)", "a) ) "]
PAIRS = [")#", ") #", ")\t#", ")\n#", ") \n #", ")\n\n#", ")\r\n#", ") #"]
WORDS = ["sql", "SQL", "Query", "where", "SELECT", "ſql", "sqlx", "no keyword", ""]
BACKS = ["", " x", " sql", "\n", "\nsql", " ) # where"]


def _family():
    for front, start, gap, pair, word, back in itertools.product(FRONTS[:3], STARTS, GAPS[:6], PAIRS, WORDS[:7], BACKS[:4]):
        yield front + start + gap + pair + word + back
    for front, start, gap, pair, word, back in itertools.product(FRONTS[3:], STARTS[:2], GAPS[6:], PAIRS[:3], WORDS[7:], BACKS[4:]):
        yield front + start + gap + pair + word + back


def _seeded(count, seed):
    pieces = [".format", ".format ", "(", ")", "#", " ", "\n", "sql", "query", "where", "x", ")#", ") #", ")\n#", ".format\n(",
              "\t", "\r", " ", "\n\n", " \n ", "select"]
    rng = random.Random(seed)
    for _ in range(count):
        head = rng.choice(["", ".format(", ".format (", ".format\n(", "x.format("]) if rng.random() < 0.8 else ""
        yield head + "".join(rng.choice(pieces) for _ in range(rng.randint(1, 16)))


def test_the_rule_is_composed_from_the_parts_its_key_declares():
    declared = RULE["start_memo"]
    source = RULE["regex"][ENTRY]
    assert declared["entry"] == ENTRY and declared["memo"] and source.startswith(declared["memo"])
    assert source != ORACLE_SOURCE and len(RULE["regex"]) == 6
    assert re.compile(declared["memo"], re.IGNORECASE).match(".format (x) # sql") is not None


def test_only_the_declared_entry_runs_in_the_memo_mode():
    modes = [mode for mode, _rx, _key in _compiled_all(_engine(True))]
    assert modes == ["plain"] * ENTRY + ["memo"]
    assert [mode for mode, _rx, _key in _compiled_all(_engine(False))] == ["plain"] * 6


def _compiled_all(engine):
    return engine._compiled_by_id[RULE_ID]


def test_the_regex_matches_like_the_oracle_at_every_offset():
    new = re.compile(RULE["regex"][ENTRY], re.IGNORECASE)
    seen = 0
    for text in itertools.chain(_family(), _seeded(6000, 11)):
        assert _every_offset(new, text) == _every_offset(ORACLE, text), repr(text)
        seen += bool(ORACLE.search(text))
    assert seen > 1000


@pytest.mark.parametrize("keyed", [True, False])
def test_every_occurrence_and_span_equal_the_oracle_with_the_key_on_and_off(keyed):
    engine = _engine(keyed)
    seen = 0
    for text in itertools.chain(_family(), _seeded(6000, 12)):
        assert _walk(engine, text) == _oracle_walk(text), repr(text)
        seen += bool(_walk(engine, text))
    assert seen > 1000


def test_the_decision_is_the_oracle_decision_on_every_channel_with_the_key_on_and_off():
    on, off = _engine(True), _engine(False)
    for text in itertools.islice(_family(), 0, None, 37):
        for channel in RULE["channel"]:
            assert _decision(on, text, channel) == _decision(off, text, channel), (channel, repr(text))
    block = [".format(x) # sql", "q.format(a)\n# where", ".format\n(a) ) # query", "x.format(a))#select"]
    for text in block:
        assert _decision(on, text, "file")[0] == "block", repr(text)


@pytest.mark.parametrize("text", [
    ".format(x) # no keyword here",
    ".format(x) sql # no word after the hash",
    ".format(x)\n# sql on the next line is a match, the word before it is not",
    ".format(x\n) # sql",
    ".format(x)\n\n\n# one more line",
    "format(x) # sql",
    ".format x) # sql",
    "K.format(x) # sql",
])
def test_the_rows_the_expression_never_matched_or_always_matched_stay_so(text):
    assert _walk(_engine(True), text) == _walk(_engine(False), text) == _oracle_walk(text)


def test_the_last_paren_of_the_line_decides_when_its_hash_stands_on_a_later_line():
    text = ".format(a) # sql\n.format(b)\n# where"
    assert _walk(_engine(True), text) == _oracle_walk(text) != []
    text = ".format(a) ) \n # query"
    assert _walk(_engine(True), text) == _oracle_walk(text) != []
    text = ".format(a) # sql ) \n # no"
    assert _walk(_engine(True), text) == _oracle_walk(text)


def test_the_rule_has_no_waiver_row():
    waivers = json.loads((Path(__file__).parent / "pattern_perf_waivers.json").read_text())
    assert RULE_ID not in waivers
