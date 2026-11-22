"""A rule may declare `start_memo`: the engine then attempts its regex only at the starts the rule names and does not
attempt a later start whose gap line a failed start already ended.

The key may only SAVE work. A keyed rule must give, for every text, the occurrences, the spans and the decision the
plain search gives. These tests use a toy rule only (no rule text of the package is in this file) and count attempts,
never seconds. A rule where a later start can win after a failed one is not allowed to carry the key, and one test
shows that the equality check goes red for such a rule.
"""
import random

import pytest

from sunglasses.engine import SunglassesEngine

RULE_ID = "TOY-MEMO"
# A start word and a paren, then a gap that needs a `)` and a `#` on its line, then a keyword.
START = r"open\s*\("
TAIL = r".*\)\s*#.*(?:sql|query)"
TOY = START + TAIL                      # the rule's own regex, composed from the parts (one source)


def _rule(regex=TOY, **extra):
    rule = {"id": RULE_ID, "name": "Toy rule", "category": "prompt_injection", "severity": "high",
            "channel": ["message"], "regex": [regex]}
    rule.update(extra)
    return rule


def _engine(keyed=True, regex=TOY, start=START, **extra):
    if keyed:
        extra["start_memo"] = {"memo": start}
    return SunglassesEngine(patterns=[_rule(regex, **extra)], mechanisms=False)


class _CountingRegex:
    """Counts the attempts the engine makes at one start (`match`) and passes everything through."""

    def __init__(self, rx, limit):
        self._rx, self.attempts, self._limit = rx, 0, limit

    def search(self, text, pos=0, endpos=None):
        return self._rx.search(text, pos, len(text) if endpos is None else endpos)

    def match(self, text, pos=0, endpos=None):
        self.attempts += 1
        assert self.attempts <= self._limit, f"more than {self._limit} attempts"
        return self._rx.match(text, pos)

    def __getattr__(self, name):
        return getattr(self._rx, name)


def _scan(engine, text, channel="message"):
    result = engine.scan(text, channel)
    return result.decision, [finding.get("id") for finding in result.findings]


def _walk(engine, text, rx=None):
    """Every occurrence the way the engine's walk asks for them: one per-text memo, each next one from one past the start."""
    mode, compiled, key = engine._compiled_by_id[RULE_ID][0]
    out, pos, memo = [], 0, {}
    while (found := engine._eval_regex(mode, rx or compiled, key, text, pos, memo)) is not None:
        out.append(found.span())
        pos = found.start() + 1
    return out


def _spans(engine, text):
    return _walk(engine, text)


def _attempts(text, limit=50, start=START, regex=TOY):
    engine = _engine(start=start, regex=regex)
    mode, rx, key = engine._compiled_by_id[RULE_ID][0]
    spy = _CountingRegex(rx, limit)
    spy.found = engine._eval_regex(mode, spy, key, text, 0, {})
    return spy


def test_a_declared_key_selects_the_memo_mode_and_no_other_rule_gets_it():
    on, off = _engine(), _engine(keyed=False)
    assert on._compiled_by_id[RULE_ID][0][0] == "memo" and (RULE_ID, 0) in on._start_memo_spec
    assert off._compiled_by_id[RULE_ID][0][0] == "plain" and not off._start_memo_spec
    engine = SunglassesEngine()
    for pid, entries in engine._compiled_by_id.items():
        for index, (mode, _rx, _key) in enumerate(entries):
            assert (mode == "memo") == ((pid, index) in engine._start_memo_spec)


def test_a_key_whose_start_is_not_in_the_regex_is_not_used():
    engine = _engine(start=r"close\s*\(")
    assert engine._compiled_by_id[RULE_ID][0][0] == "plain" and not engine._start_memo_spec


def test_a_key_names_the_regex_entry_it_belongs_to():
    rule = _rule(start_memo={"memo": START, "entry": 1})
    rule["regex"] = [r"unrelated\s+words", TOY]
    modes = [m for m, _r, _k in SunglassesEngine(patterns=[rule], mechanisms=False)._compiled_by_id[RULE_ID]]
    assert modes == ["plain", "memo"]


def test_a_gap_line_whose_first_start_failed_is_attempted_once():
    line = "open( " * 5 + "x"
    spy = _attempts(line)
    assert spy.attempts == 1 and spy.found is None


def test_the_line_that_ends_is_the_line_where_the_failed_start_ends():
    spy = _attempts("open\n( open( open(")
    assert spy.attempts == 1 and spy.found is None
    spy = _attempts("open( x\nopen\n( open( y")
    assert spy.attempts == 2 and spy.found is None


def test_a_second_line_gets_its_own_attempt():
    spy = _attempts("open( open( open(\nopen( open(\nopen(")
    assert spy.attempts == 3 and spy.found is None


@pytest.mark.parametrize("gap", ["\n", " \n ", "\n\n"])
def test_a_paren_that_ends_on_a_later_line_is_not_skipped(gap):
    text = "open" + gap + "(x) # sql"
    assert _spans(_engine(), text) == _spans(_engine(keyed=False), text) != []
    assert _scan(_engine(), text) == _scan(_engine(keyed=False), text)
    assert _scan(_engine(), text)[0] != "allow"


def test_a_failed_start_does_not_hide_a_start_that_ends_on_the_next_line():
    text = "open( x\nopen\n( y) # sql"
    assert _spans(_engine(), text) == _spans(_engine(keyed=False), text) != []


def test_two_occurrences_on_two_lines_are_both_found():
    text = "open(a) # sql\nopen(b) # query"
    assert _spans(_engine(), text) == _spans(_engine(keyed=False), text)
    assert len(_spans(_engine(), text)) == 2


def test_a_failed_start_on_the_first_line_leaves_a_match_on_the_second():
    text = "open( x\nopen(a) # sql"
    assert _spans(_engine(), text) == _spans(_engine(keyed=False), text) == [(8, len(text))]


@pytest.mark.parametrize("word", ["open(", "OPEN(", "oPen(", "open ("])
def test_the_start_is_found_by_the_rules_own_flags(word):
    text = word + "x) # sql"
    assert _spans(_engine(), text) == _spans(_engine(keyed=False), text) != []
    assert _scan(_engine(), text) == _scan(_engine(keyed=False), text)


@pytest.mark.parametrize("spelling", ["Keep(x) # sql", "keep(x) # sql", "KEEP(x) # sql"])
def test_a_folded_letter_in_the_start_still_starts(spelling):
    regex = r"keep\s*\(" + TAIL
    on, off = _engine(regex=regex, start=r"keep\s*\("), _engine(keyed=False, regex=regex)
    assert _spans(on, spelling) == _spans(off, spelling) != []


def test_the_failed_state_is_one_walk_and_one_text():
    engine = _engine()
    first = _scan(engine, "open( x")
    second = _scan(engine, "open(x) # sql")
    again = _scan(engine, "open( x")
    assert first[0] == "allow" and second[0] != "allow" and again[0] == "allow"
    assert _walk(engine, "open(x) # sql") == _walk(engine, "open(x) # sql")


def test_the_attempt_state_is_not_kept_on_the_engine():
    engine = _engine()
    before = {name: repr(value) for name, value in vars(engine).items() if name != "_floor_cache"}
    _scan(engine, "open( open( open(")
    after = {name: repr(value) for name, value in vars(engine).items() if name != "_floor_cache"}
    assert before == after


def test_key_on_and_key_off_agree_on_a_seeded_family():
    pieces = ["open(", "open (", "open\n(", "open\n", "(", ")", ") ", "\n", "#", "# ", " sql", " query", "x", " ", "\n\n"]
    rng = random.Random(1)
    on, off = _engine(), _engine(keyed=False)
    for _ in range(400):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 16)))
        assert _spans(on, text) == _spans(off, text), repr(text)
        assert _scan(on, text) == _scan(off, text), repr(text)


def test_a_plain_start_is_always_tried_and_never_ends_a_line():
    regex = r"(?:(?:open\s*\()|(?:wide\s*\())" + TAIL
    rule = _rule(regex=regex, start_memo={"memo": r"open\s*\(", "plain": r"wide\s*\("})
    keyed = SunglassesEngine(patterns=[rule], mechanisms=False)
    plain = SunglassesEngine(patterns=[_rule(regex=regex)], mechanisms=False)
    for text in ("open( wide(x) # sql", "wide( open(x) # sql", "open( x wide( y\nopen(z) # query", "wide( wide(x) # sql"):
        assert _spans(keyed, text) == _spans(plain, text), repr(text)
    assert keyed._compiled_by_id[RULE_ID][0][0] == "memo"


def test_a_failed_plain_start_does_not_end_the_line_of_a_memo_start():
    regex = r"(?:wide\s*\(zz|open\s*\(" + TAIL + ")"
    rule = _rule(regex=regex, start_memo={"memo": r"open\s*\(", "plain": r"wide\s*\("})
    keyed = SunglassesEngine(patterns=[rule], mechanisms=False)
    plain = SunglassesEngine(patterns=[_rule(regex=regex)], mechanisms=False)
    for text in ("wide(q open(x) # sql", "wide(q wide(q open(x) # sql", "open( wide(zz open(x) # sql"):
        assert _spans(keyed, text) == _spans(plain, text) != [], repr(text)


def test_the_equality_check_goes_red_for_a_rule_where_a_later_start_can_win():
    wrong = r"open\(ok"                      # the first start fails on `no`, the second wins: this rule may not carry the key
    text = "open(no open(ok"
    off = _engine(keyed=False, regex=wrong, start=r"open\(")
    on = _engine(regex=wrong, start=r"open\(")
    assert _spans(off, text) == [(8, 15)]
    assert _spans(on, text) != _spans(off, text)
