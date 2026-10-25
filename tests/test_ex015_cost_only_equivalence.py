"""GLS-EX-015 carries a guarded form of its regex that finds exactly what the same regex without the guards finds.

Without the guards the regex is

    (?i)A.{0,100}B.{0,220}C.{0,100}D

with A, B, C and D four alternations of plain words. The shipped form puts a lookahead in front of
each later part that asks only for something every full match already needs: a B within reach of
the A, a D within reach of the A, a D within reach of the B, a C within reach of the B, and the
first letter of each part before the part itself. A lookahead consumes nothing, so a path it
rejects was a path that could not finish, and the match the search returns (start, end, text) is
the one the plain form returns.

What these tests pin:

1. The rule carries the guarded form, and the first guard after the opener asks for the B (an
   implementation pin, not a performance check).
2. The two forms agree on the full span and text on a fixed table, on a sweep of every gap at its
   bound and one either side, on LF, CRLF and CR in the gaps, on the letters whose case folding
   reaches outside ASCII, and on seeded random strings.
3. The engine, scanning with the shipped rule and with the plain form, returns the same decision
   and the same findings on a subset of those texts. The engine evaluates a regex that starts with
   a lookahead as a co-occurrence test, so agreement of the bare regexes is not enough.
4. The table notices a narrowed guard: narrowing each guard's upper bound by one, or deleting one
   character from one first-letter class, makes the guarded form disagree with the plain one on
   some text in the table. Widening or removing a guard keeps the matches the same, and no test
   here claims otherwise.
"""
import itertools
import random
import re

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

A = r"(?:read|open|search|grep|find)"
B = r"(?:\.env|credentials|token|secret|id_rsa|config)"
C = r"(?:include|embed|paste|store|write|attach)"
D = r"(?:issue|ticket|commit|pull request|pr|artifact|log|summary|notes|report)"

PLAIN = "(?i)" + A + ".{0,100}" + B + ".{0,220}" + C + ".{0,100}" + D

# Guards as they are written in the rule, built from the same four parts.
GUARDED = (
    "(?i)" + A
    + "(?=.{0,100}(?=[.ctsi])" + B + ")"
    + "(?=.{0,438}(?=[itcpalsnr])" + D + ")"
    + ".{0,100}(?=[.ctsi])" + B
    + "(?=.{0,327}(?=[itcpalsnr])" + D + ")"
    + "(?=.{0,220}(?=[iepswa])" + C + ")"
    + ".{0,220}(?=[iepswa])" + C
    + ".{0,100}(?=[itcpalsnr])" + D
)

WORDS_A = ["read", "open", "search", "grep", "find"]
WORDS_B = [".env", "credentials", "token", "secret", "id_rsa", "config"]
WORDS_C = ["include", "embed", "paste", "store", "write", "attach"]
WORDS_D = ["issue", "ticket", "commit", "pull request", "pr", "artifact", "log", "summary", "notes", "report"]


def _rule():
    (rule,) = [r for r in PATTERNS if r["id"] == "GLS-EX-015"]
    return rule


def _same(a, b, text):
    """Same hit: same span, same matched text, same groups."""
    assert bool(a) == bool(b), repr(text)[:200]
    if a:
        assert a.span() == b.span(), repr(text)[:200]
        assert a.group(0) == b.group(0), repr(text)[:200]
        assert a.groups() == b.groups(), repr(text)[:200]


def _words_table():
    """Every combination of one word per part, joined by a space."""
    return [" ".join(p) for p in itertools.product(WORDS_A, WORDS_B, WORDS_C, WORDS_D)]


def _gap_sweep():
    """Each gap at its bound and one either side, with the longest and a short word of each part,
    and, in additional cases, a gap filled with a line break."""
    out = []
    for a, b, c, d in itertools.product(["read", "search"], ["credentials", ".env"], ["include", "attach"],
                                        ["pull request", "pr", "issue"]):
        for g1, g2, g3 in itertools.product([0, 1, 99, 100, 101], [0, 1, 219, 220, 221], [0, 1, 99, 100, 101]):
            out.append(a + "q" * g1 + b + "q" * g2 + c + "q" * g3 + d)
    for a, b, c, d in [("search", "credentials", "include", "pull request"), ("read", ".env", "write", "pr")]:
        for sep in ("\n", "\r\n", "\r"):
            for g in (1, 2, 50, 99, 100):
                out.append(a + "q" * g + b + "q" * 5 + c + "q" * 5 + d)
                out.append(a + "q" * 5 + sep + "q" * g + b + "q" * 5 + c + "q" * 5 + d)
                out.append(a + "q" * 5 + b + "q" * 5 + sep + "q" * g + c + "q" * 5 + d)
                out.append(a + "q" * 5 + b + "q" * 5 + c + "q" * 5 + sep + "q" * g + d)
    return out


# The characters that match a plain letter under IGNORECASE without being that letter or its upper case.
FOLDS = {"i": ["İ", "ı", "I"], "k": ["K", "K"], "s": ["ſ", "S"]}


def _fold_table():
    out = []
    for text in ["read .env write issue", "search credentials include ticket", "find token store summary",
                 "grep secret paste notes", "open id_rsa embed pull request", "read config attach report",
                 "find secret write commit", "open token paste artifact"]:
        for letter, subs in FOLDS.items():
            for sub in subs:
                for pos in [m.start() for m in re.finditer(letter, text)]:
                    out.append(text[:pos] + sub + text[pos + 1:])
        out.append(text.upper())
        out.append(text.title())
    return out


NOISE = ["", " ", "\n", "x", "q", "\t", ",", ".", "a b c", "and then", "\r\n", "\r"]


def _random_texts(seed, count):
    rng = random.Random(seed)
    words = WORDS_A + WORDS_B + WORDS_C + WORDS_D + NOISE
    fillers = ["q", " ", "ab", "x\n", "0"]
    out = []
    for _ in range(count):
        parts = []
        for _ in range(rng.randint(3, 12)):
            parts.append(rng.choice(words))
            parts.append(rng.choice(fillers) * rng.choice([0, 0, 0, 0, 0, 1, 1, 1, 5, 5, 40, 90, 100, 101, 150, 220, 221, 330, 440]))
        out.append("".join(parts))
    return out


GAPS = [0, 1, 2, 7, 40, 99, 100, 101, 150, 219, 220, 221, 330]


def _chain_texts(seed, count):
    """The four parts in order with random words, random gap lengths and noise in the gaps, and now and
    then one part left out, doubled or moved, so most strings hold a near miss."""
    rng = random.Random(seed)
    out = []
    for _ in range(count):
        parts = [rng.choice(WORDS_A), rng.choice(WORDS_B), rng.choice(WORDS_C), rng.choice(WORDS_D)]
        roll = rng.random()
        if roll < 0.15:
            del parts[rng.randrange(4)]
        elif roll < 0.25:
            parts.insert(rng.randrange(5), rng.choice(WORDS_A + WORDS_B + WORDS_C + WORDS_D))
        elif roll < 0.30:
            rng.shuffle(parts)
        text = rng.choice(["", "x ", "\n"])
        for part in parts:
            text += part + rng.choice(["q", " ", "ab", "x\n", "0", "\r"]) * rng.choice(GAPS)
        out.append(text)
    return out


def test_the_rule_carries_the_guarded_form():
    assert _rule()["regex"] == [GUARDED]
    assert GUARDED != PLAIN


def test_the_first_guard_after_the_opener_asks_for_the_secret_word():
    assert GUARDED.startswith("(?i)" + A + "(?=.{0,100}(?=[.ctsi])" + B + ")")
    assert _rule()["regex"][0].startswith("(?i)" + A + "(?=.{0,100}(?=[.ctsi])" + B + ")")


def _near_miss_texts():
    """Text that keeps offering the opening parts without the later ones, at three sizes."""
    units = ["read ", "read open find ", "read credentials ", "read credentials include ",
             "read " + "q" * 95 + " token ", "read token report ", "The quick brown fox reads a file. "]
    return [(unit * (size // len(unit) + 1))[:size] for unit in units for size in (2048, 8192, 32768)]


def test_they_agree_on_text_that_keeps_offering_the_opening_parts():
    old, new = re.compile(PLAIN), re.compile(GUARDED)
    for text in _near_miss_texts():
        a, b = list(old.finditer(text)), list(new.finditer(text))
        assert [(m.span(), m.group(0)) for m in a] == [(m.span(), m.group(0)) for m in b], text[:60]


def test_the_plain_and_the_guarded_form_agree_on_the_word_table():
    old, new = re.compile(PLAIN), re.compile(GUARDED)
    for text in _words_table():
        _same(old.search(text), new.search(text), text)


def test_they_agree_with_every_gap_at_its_bound_and_one_either_side():
    old, new = re.compile(PLAIN), re.compile(GUARDED)
    hits = 0
    for text in _gap_sweep():
        a = old.search(text)
        hits += bool(a)
        _same(a, new.search(text), text)
    assert hits > 100


def test_they_agree_on_the_letters_whose_case_folding_leaves_ascii():
    old, new = re.compile(PLAIN), re.compile(GUARDED)
    for text in _fold_table():
        _same(old.search(text), new.search(text), text)


def test_they_agree_on_seeded_random_strings():
    old, new = re.compile(PLAIN), re.compile(GUARDED)
    hits = 0
    for text in _random_texts(15, 20000):
        a = old.search(text)
        hits += bool(a)
        _same(a, new.search(text), text)
    assert hits > 20


def test_they_agree_on_seeded_strings_built_from_the_four_parts():
    old, new = re.compile(PLAIN), re.compile(GUARDED)
    hits = 0
    for text in _chain_texts(2015, 40000):
        a = old.search(text)
        hits += bool(a)
        _same(a, new.search(text), text)
    assert 4000 < hits < 38000, hits


def _answer(result):
    """The decision and the findings, without the rule's own regex text (which is what differs)."""
    return result.decision, [{k: v for k, v in f.items() if k != "regex"} for f in result.findings]


def _engine(regex):
    rule = dict(_rule())
    rule["regex"] = [regex]
    return SunglassesEngine(patterns=[rule], mechanisms=False)


@pytest.fixture(scope="module")
def engines():
    return _engine(PLAIN), SunglassesEngine(patterns=[_rule()], mechanisms=False)


def test_the_engine_gives_the_same_answer_with_either_form(engines):
    old, new = engines
    texts = _words_table()[::7] + _gap_sweep()[::5] + _fold_table() + _random_texts(150, 1500) + _chain_texts(151, 2500)
    held = 0
    for text in texts:
        for channel in tuple(_rule()["channel"]):
            a, b = old.scan(text, channel=channel), new.scan(text, channel=channel)
            assert _answer(a) == _answer(b), (channel, text[:200])
            held += a.decision != "allow"
    assert held > 100


def test_the_engine_answer_does_not_depend_on_the_regex_leading_with_a_lookahead(engines):
    """The engine evaluates a regex that starts with a lookahead as a co-occurrence test: matched from
    the start of a short text, or from the start of each overlapping window of a long one, never by a
    plain search. The rule's first part is a consuming one, so it stays under the plain search, and a
    match in the middle of this short text is found."""
    _, new = engines
    result = new.scan("Logging how-to: read config documentation, then write a public greeting using logging.",
                      channel="file")
    assert any(f["id"] == "GLS-EX-015" for f in result.findings)
    assert not _rule()["regex"][0].startswith("(?i)(?=")


def _mutants():
    """Each guard bound narrowed by one, and each character deleted from one first-letter class."""
    out = []
    for old, new in [("(?=.{0,100}(?=[.ctsi])", "(?=.{0,99}(?=[.ctsi])"), ("{0,438}", "{0,437}"), ("{0,327}", "{0,326}"),
                     ("(?=.{0,220}(?=[iepswa])", "(?=.{0,219}(?=[iepswa])")]:
        assert GUARDED.count(old) == 1, old
        out.append(("bound " + old, GUARDED.replace(old, new)))
    for cls in ("[itcpalsnr]", "[.ctsi]", "[iepswa]"):
        start = 0
        while True:
            at = GUARDED.find(cls, start)
            if at < 0:
                break
            for k, letter in enumerate(cls[1:-1]):
                edited = cls[:1 + k] + cls[2 + k:]
                out.append((f"class {cls} at {at} without {letter!r}", GUARDED[:at] + edited + GUARDED[at + len(cls):]))
            start = at + 1
    return out


def test_each_guard_is_needed_by_the_table():
    texts = _words_table() + _gap_sweep()
    old = re.compile(PLAIN)
    expected = [old.search(t) for t in texts]
    survivors = []
    for name, source in _mutants():
        rx = re.compile(source)
        for text, a in zip(texts, expected):
            b = rx.search(text)
            if bool(a) != bool(b) or (a and a.span() != b.span()):
                break
        else:
            survivors.append(name)
    assert not survivors, survivors
