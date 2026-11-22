"""The concealment action rule (GLS-PI-015) reports the same occurrences, spans and decisions as ORACLE_SOURCE, a frozen
copy of the rule's expression in release 0.6.26 that is not read from the package. The rule's regex must match like it
at EVERY offset of every text of the families below, the engine must report the same occurrences and spans with the key
on and with the key off, and the decision must be the same. There is no timing and no long text in this file.
"""
import itertools
import json
import random
import re
from pathlib import Path

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

RULE_ID = "GLS-PI-015"
ORACLE_SOURCE = (r"(?i)(?:do not mention|keep.*out of (?:the )?(?:summary|report|final answer)|avoid clutter|quietly|silently)"
                 r".{0,120}(?:upload|send|attach|collect|gather|include)")
ORACLE = re.compile(ORACLE_SOURCE)
RULE = next(p for p in PATTERNS if p["id"] == RULE_ID)
VERBS = ["upload", "send", "attach", "collect", "gather", "include"]
PLAIN_OPENERS = ["do not mention", "avoid clutter", "quietly", "silently"]
KEEP_OPENERS = ["keep this out of the report", "keep it out of summary", "keep it out of the final answer", "keep out of report"]
OPENERS = PLAIN_OPENERS + KEEP_OPENERS


def _engine(keyed):
    rule = {k: v for k, v in RULE.items() if keyed or k != "start_memo"}
    return SunglassesEngine(patterns=[rule], mechanisms=False)


def _walk(engine, text):
    mode, rx, key = engine._compiled_by_id[RULE_ID][0]
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
    return result.decision, sorted((f.get("id"), f.get("severity")) for f in result.findings)


def _seeded(count, seed):
    pieces = ["keep", "Keep ", "out of ", "the ", "report", "summary", "final answer", "send", "upload", "attach", "collect",
              " ", "\n", "x", "quietly", "do not mention", "avoid clutter", "silently", "include", "gather", "K", "ſ",
              "keep it out of the report ", "\n\n"]
    rng = random.Random(seed)
    for _ in range(count):
        yield "".join(rng.choice(pieces) for _ in range(rng.randint(1, 16)))


def _family():
    for opener, gap, verb in itertools.product(OPENERS, [0, 1, 2, 60, 118, 119, 120, 121, 122], VERBS):
        yield opener + "x" * gap + verb
    for opener, join, verb in itertools.product(OPENERS, [" ", "\n", " \n ", "\n\n"], VERBS):
        yield "keep a " + opener + join + verb
        yield opener + join + verb + join + "keep it out of the report " + verb


def test_the_rule_is_composed_from_the_parts_its_key_declares():
    declared, source = RULE["start_memo"], RULE["regex"][0]
    assert declared["memo"] and declared["plain"] and declared["memo"] in source and declared["plain"] in source
    assert declared.get("entry", 0) == 0 and len(RULE["regex"]) == 1
    assert re.compile(declared["memo"], re.IGNORECASE).search("Keep") and not re.compile(declared["plain"], re.IGNORECASE).search("keep")


def test_the_rule_runs_in_the_memo_mode_only_with_its_key():
    assert _engine(True)._compiled_by_id[RULE_ID][0][0] == "memo"
    assert _engine(False)._compiled_by_id[RULE_ID][0][0] == "plain"


def test_the_regex_matches_like_the_oracle_at_every_offset():
    new = re.compile(RULE["regex"][0])
    for text in itertools.chain(_family(), _seeded(5000, 21)):
        assert _every_offset(new, text) == _every_offset(ORACLE, text), repr(text)


@pytest.mark.parametrize("gap", [0, 1, 119, 120, 121, 122])
@pytest.mark.parametrize("opener", OPENERS)
@pytest.mark.parametrize("verb", VERBS)
def test_the_action_word_window_is_the_oracle_window_on_both_sides_of_its_edge(gap, opener, verb):
    text = opener + "x" * gap + verb
    assert _walk(_engine(True), text) == _oracle_walk(text)
    assert bool(_oracle_walk(text)) == (gap <= 120)


SHAPES = ["keep it out of the report\nsend", "keep it out of the report send\nkeep it out of summary upload", "QUIETLY send",
          "Silently Upload", "do not mention\nsend", "x keep out of final answer attach", "keep Keep out of the report send",
          "eaſy keep out of the summary send", "quietly\n\nsend", "keep keep out of the report collect",
          "keep out of out of the summary gather", "Keep it out of the report send", "ſilently send",
          "keep it out of the report quietly send", "keep it out of the summary\nkeep it out of the report include"]


@pytest.mark.parametrize("text", SHAPES)
@pytest.mark.parametrize("keyed", [True, False])
def test_shapes_equal_the_oracle(text, keyed):
    assert _walk(_engine(keyed), text) == _oracle_walk(text) != [] or _oracle_walk(text) == []
    assert _walk(_engine(keyed), text) == _oracle_walk(text)


@pytest.mark.parametrize("other", PLAIN_OPENERS)
@pytest.mark.parametrize("verb", VERBS)
def test_a_failed_keep_on_the_line_does_not_hide_another_opener(other, verb):
    text = "keep this x " + other + " " + verb
    assert _walk(_engine(True), text) == _oracle_walk(text) != []
    text = "keep this out of the report x keep a " + other + " " + verb
    assert _walk(_engine(True), text) == _oracle_walk(text) != []


@pytest.mark.parametrize("keyed", [True, False])
def test_every_occurrence_and_span_equal_the_oracle_with_the_key_on_and_off(keyed):
    engine, seen = _engine(keyed), 0
    for text in itertools.chain(_family(), _seeded(6000, 22)):
        assert _walk(engine, text) == _oracle_walk(text), repr(text)
        seen += bool(_walk(engine, text))
    assert seen > 1000


def test_the_decision_is_the_oracle_decision_on_every_channel_with_the_key_on_and_off():
    on, off = _engine(True), _engine(False)
    for text in itertools.islice(_family(), 0, None, 11):
        for channel in RULE["channel"]:
            assert _decision(on, text, channel) == _decision(off, text, channel), (channel, repr(text))
    for text in itertools.islice(_seeded(400, 23), 0, None, 1):
        for channel in RULE["channel"]:
            assert _decision(on, text, channel) == _decision(off, text, channel), (channel, repr(text))


def test_a_word_or_label_in_front_does_not_change_the_decision():
    words = (SunglassesEngine.TRUE_NEGATIONS + SunglassesEngine.FRAMING_LABELS)[:12]
    on, off = _engine(True), _engine(False)
    for word in [""] + words:
        for opener in OPENERS:
            text = (word + " " + opener + " send").strip()
            for channel in RULE["channel"]:
                assert _decision(on, text, channel) == _decision(off, text, channel), (word, opener, channel)
    assert _decision(on, "quietly send the file", "file")[0] != "allow"


def test_the_rule_has_no_waiver_row():
    waivers = json.loads((Path(__file__).parent / "pattern_perf_waivers.json").read_text())
    assert RULE_ID not in waivers
