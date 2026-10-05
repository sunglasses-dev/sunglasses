"""No rule may chain its lookaheads with a consuming wildcard between them.

`^(?!G)(?=.*A).*(?=.*B).*(?=.*C).*$` reads like three independent checks, but
the `.*` between the lookaheads is a backtracking point. When A and B are in a
window and C is not, the first `.*` gives back one character at a time, the
second does the same inside every one of those, and each step runs `(?=.*C)`
over the rest of the window: cubic in the window length. GLS-SMP-023 ran far
past the scan budget on inputs of a few kilobytes, while the stacked form
`^(?!G)(?=.*A)(?=.*B)(?=.*C).*$` is linear.

The two forms accept exactly the same texts. `(?=.*X)` is monotone in where it
starts (if X occurs at or after position q it occurs at or after 0), so three
lookaheads chained by `.*` succeed if and only if A, B and C each occur in the
window, which is what the stacked form asks at position 0. Both then consume the
window with `.*$`, so `group(0)` and `start()` agree too.

Three things are pinned here:
  1. the shape itself, found by PARSING every shipped regex, never by grep, so a
     `[\\s\\S]*` or a wildcard inside a group cannot hide from it;
  2. the two rules that carried it, against a frozen copy of their old source,
     on a corpus and on generated texts;
  3. one wide-margin timing row for the input that used to run far past the scan budget.
"""
import json
import pathlib
import random
import re
import time

import pytest

try:  # 3.11+ keeps the parser under `re`; older versions only have sre_parse
    import re._constants as _sc
    import re._parser as _sp
except ImportError:  # pragma: no cover - exercised on 3.9 and 3.10
    import sre_constants as _sc
    import sre_parse as _sp

from sunglasses import _prefilter
from sunglasses.engine import SunglassesEngine
from sunglasses.mechanisms import MECHANISM_PATTERNS
from sunglasses.patterns import PATTERNS

ROOT = pathlib.Path(__file__).resolve().parents[1]
RULES = ("GLS-SMP-023", "GLS-AW-613")


# ---------------------------------------------------------------------------
# 1. The shape, found by parsing
# ---------------------------------------------------------------------------

def _is_any_char(item):
    """True for `.` and for a class that holds every character, like [\\s\\S]."""
    op, av = item
    if op == _sc.ANY:
        return True
    if op != _sc.IN:
        return False
    categories = {a for o, a in av if o == _sc.CATEGORY}
    negated = any(o == _sc.NEGATE for o, _ in av)
    pairs = ((_sc.CATEGORY_SPACE, _sc.CATEGORY_NOT_SPACE),
             (_sc.CATEGORY_WORD, _sc.CATEGORY_NOT_WORD),
             (_sc.CATEGORY_DIGIT, _sc.CATEGORY_NOT_DIGIT))
    if not negated and any(a in categories and b in categories for a, b in pairs):
        return True
    return negated and all(o == _sc.NEGATE for o, _ in av)  # [^] holds everything


def _is_unbounded_wildcard(op, av):
    if op not in (_sc.MAX_REPEAT, _sc.MIN_REPEAT):
        return False
    low, high, body = av
    return high == _sc.MAXREPEAT and len(body) == 1 and _is_any_char(body[0])


def _bodies(op, av):
    """The sub-sequences an item holds, whatever the Python version calls it."""
    if op in (_sc.MAX_REPEAT, _sc.MIN_REPEAT):
        return [av[2]]
    if op == _sc.SUBPATTERN:
        return [av[3]]
    if op == _sc.BRANCH:
        return list(av[1])
    if op == _sc.GROUPREF_EXISTS:
        return [arm for arm in av[1:] if arm is not None]
    if hasattr(_sc, "ATOMIC_GROUP") and op == _sc.ATOMIC_GROUP:
        return [av]
    return []


def _can_swallow_anything(op, av):
    """An unbounded wildcard, or a group, branch or repeat with one inside it at
    the top of its own sequence, so `(?:.*)` and `(?:x|.*)` cannot hide one."""
    if _is_unbounded_wildcard(op, av):
        return True
    return any(_can_swallow_anything(o, a) for body in _bodies(op, av) for o, a in body)


def _lookahead_gaps(source):
    """How many items sit BETWEEN two lookaheads of `source` and can swallow an
    unbounded run of characters. The `.*$` that ends a stacked predicate is
    after the last lookahead, so it does not count."""
    return _gaps_in(list(_sp.parse(source, re.IGNORECASE)))


def _gaps_in(seq):
    total, pending, seen = 0, 0, False
    for op, av in seq:
        if op in (_sc.ASSERT, _sc.ASSERT_NOT):
            direction, body = av
            if direction == 1:
                if seen:
                    total += pending
                seen, pending = True, 0
            total += _gaps_in(body)
            continue
        if seen and _can_swallow_anything(op, av):
            pending += 1
        for body in _bodies(op, av):
            total += _gaps_in(body)
    return total


def _every_regex():
    for p in list(PATTERNS) + list(MECHANISM_PATTERNS):
        for source in p.get("regex", []):
            yield p["id"], source


def test_no_shipped_rule_chains_lookaheads_with_a_wildcard():
    offenders, parsed = [], 0
    for rule_id, source in _every_regex():
        try:
            gaps = _lookahead_gaps(source)
        except re.error:
            continue  # the engine skips a regex that does not compile
        parsed += 1
        if gaps:
            offenders.append(f"{rule_id}: {gaps} wildcard(s) between lookaheads")
    assert parsed > 1000, f"the sweep only parsed {parsed} regexes, so it measured nothing"
    assert offenders == [], (
        "a consuming `.*` or `[\\s\\S]*` between lookaheads can be superlinear in the window "
        "when the later signals are absent: quadratic with one gap, cubic with two. "
        "Stack the lookaheads at the start "
        "instead, `(?=.*A)(?=.*B)(?=.*C).*$`. Offenders:\n  " + "\n  ".join(offenders))


@pytest.mark.parametrize("source, expected", [
    # the exact old SMP-023 shape: two wildcards between three lookaheads
    (r"(?is)^(?!.*x)(?=.*a).*(?=.*b).*(?=.*c).*$", 2),
    # the same three signals stacked: nothing between them
    (r"(?is)^(?!.*x)(?=.*a)(?=.*b)(?=.*c).*$", 0),
    # a trailing wildcard after the LAST lookahead is how the stacked form ends
    (r"(?is)(?=.*a).*$", 0),
    # the all-characters class spelling
    (r"(?=.*a)[\s\S]*(?=.*b)", 1),
    (r"(?=.*a)[\w\W]*(?=.*b)", 1),
    # hidden inside a group and inside a branch
    (r"(?=.*a)(?:.*)(?=.*b)", 1),
    (r"(?=.*a)(?:x|.*)(?=.*b)", 1),
    # a bounded gap is not unbounded
    (r"(?=.*a).{0,20}(?=.*b)", 0),
    # a negative lookahead counts as an assertion too
    (r"^(?!.*x).*(?=.*b)", 1),
    # lookbehind does not
    (r"(?<=a).*(?=.*b)", 0),
])
def test_the_sweep_can_see_the_shape_and_only_the_shape(source, expected):
    assert _lookahead_gaps(source) == expected


# ---------------------------------------------------------------------------
# 2. Equivalence with the old source, for both rules
# ---------------------------------------------------------------------------

# Frozen copies of the sources before the change, kept ONLY as the reference the
# new ones are measured against. They are not rules and are never loaded.
OLD = {
    "GLS-SMP-023": r"""(?is)^(?!.*\b(?:documentation|security\s+guide|unit\s+test|fixture|incident\s+report|postmortem|defensive|must\s+not|do\s+not|reject|quarantine|fail[- ]closed|benign|safe\s+example)\b)(?=.*(?:schema[- ]valid|valid[- ]schema|valid\s+schema|structured\s+threat|json)).*(?=.*(?:cross[- ]bound|cross[- ]bind|mis[- ]bind|rebind|wrong\s+(?:actor|entity|location)|relation\s+mismatch|field\s+binding)).*(?=.*(?:accept|allow|authoriz|rank|verif|trust)).*$""",
    "GLS-AW-613": r"""(?is)^(?!.*\b(?:defensive|unit\s+test|security\s+training|blocked\s+payload|do\s+not\s+obey|must\s+not|requires\s+explicit\s+review)\b)(?=.*"turns"\s*:\s*\[)(?=.*"role"\s*:\s*"assistant").*(?=.*"approval"\s*:\s*"(?:final|execute)")(?=.*"review"\s*:\s*"(?:skipped|stale)")(?=.*"next_turn"\s*:\s*"too_late").*$""",
}


def _entry(rule_id):
    return next(p for p in PATTERNS if p["id"] == rule_id)


def _engine_for(rule_id, regex):
    engine = SunglassesEngine(patterns=[dict(_entry(rule_id), regex=[regex])],
                              mechanisms=False)
    (mode, rx, guards), = engine._compiled_by_id[rule_id]
    return engine, mode, rx, guards


def _verdict(rule_id, regex_source, text):
    engine, mode, rx, guards = _engines()[(rule_id, regex_source)]
    match = engine._eval_regex(mode, rx, guards, text)
    return None if match is None else (match.start(), match.end(), match.group(0))


_BUILT = {}


def _engines():
    if not _BUILT:
        for rule_id in RULES:
            for source in (OLD[rule_id], _entry(rule_id)["regex"][0]):
                _BUILT[(rule_id, source)] = _engine_for(rule_id, source)
    return _BUILT


def _agree(rule_id, text):
    new_source = _entry(rule_id)["regex"][0]
    return _verdict(rule_id, OLD[rule_id], text), _verdict(rule_id, new_source, text)


@pytest.mark.parametrize("rule_id", RULES)
def test_the_new_source_is_the_old_one_with_only_the_gaps_removed(rule_id):
    new_source = _entry(rule_id)["regex"][0]
    assert new_source == OLD[rule_id].replace(").*(?=", ")(?=")
    assert _lookahead_gaps(OLD[rule_id]) >= 1
    assert _lookahead_gaps(new_source) == 0


@pytest.mark.parametrize("rule_id", RULES)
def test_the_engine_treats_the_new_source_like_the_old_one(rule_id):
    """Same mode, same document-wide guards, same prefilter requirement, so the
    prefilter skips exactly the texts it skipped before."""
    new_source = _entry(rule_id)["regex"][0]
    _, old_mode, old_rx, old_guards = _engines()[(rule_id, OLD[rule_id])]
    new_engine, new_mode, new_rx, new_guards = _engines()[(rule_id, new_source)]
    old_engine = _engines()[(rule_id, OLD[rule_id])][0]
    assert old_mode == new_mode == "guarded"
    assert [g.pattern for g in old_guards] == [g.pattern for g in new_guards]
    assert (old_engine._regex_requirement[id(old_rx)]
            == new_engine._regex_requirement[id(new_rx)])
    assert _prefilter.requirement(new_rx.pattern)  # still has something to skip on


SMP_POSITIVE = ("The extractor emits a schema-valid record. The fields were "
                "cross-bound to the wrong actor. The consumer will accept the record.")
SMP_MISSING_THIRD = ("The extractor emits a schema-valid record. The fields were "
                     "cross-bound to the wrong actor. Nothing else follows here.")
AW_POSITIVE = ('{"turns": [{"role": "assistant", "x": 1}], "approval": "execute", '
               '"review": "skipped", "next_turn": "too_late"}')
AW_MISSING_LAST = ('{"turns": [{"role": "assistant", "x": 1}], "approval": "execute", '
                   '"review": "skipped"}')


@pytest.mark.parametrize("rule_id, text, matches", [
    ("GLS-SMP-023", SMP_POSITIVE, True),
    ("GLS-SMP-023", SMP_MISSING_THIRD, False),
    ("GLS-SMP-023", SMP_POSITIVE + " This is a benign example for documentation.", False),
    ("GLS-AW-613", AW_POSITIVE, True),
    ("GLS-AW-613", AW_MISSING_LAST, False),
    ("GLS-AW-613", AW_POSITIVE + " This is defensive guidance.", False),
])
def test_crafted_positives_and_negatives(rule_id, text, matches):
    old, new = _agree(rule_id, text)
    assert old == new
    assert (new is not None) is matches


def test_a_signal_split_by_a_window_edge_agrees_in_both_forms():
    """COOCCUR_WINDOW is 1200 with stride 600. Move a complete positive across
    every kind of edge. The padding is short words so no window is slow in the
    old form (all three signals are always inside the one window that matches)."""
    pad = "x " * 700
    for k in (0, 300, 590, 610, 1100, 1190, 1210, 2400):
        old, new = _agree("GLS-SMP-023", pad[:k] + SMP_POSITIVE + pad)
        assert old == new and new is not None, k
        old, new = _agree("GLS-AW-613", pad[:k] + AW_POSITIVE + pad)
        assert old == new and new is not None, k


SMP_VOCAB = {
    "A": ["schema-valid", "valid schema", "structured threat", "json", "JSON"],
    "B": ["cross-bound", "cross bind", "mis-bind", "rebind", "wrong actor",
          "wrong location", "relation mismatch", "field binding"],
    "C": ["accept", "allow", "authorized", "rank", "verified", "trust"],
    "G": ["documentation", "unit test", "fixture", "benign", "safe example", "must not"],
    "F": ["alpha", "beta", "the", "record", "x", "\n", " ", "12345", "{", "}"],
}
AW_VOCAB = {
    "T": ['"turns": [', '"TURNS" : ['], "R": ['"role": "assistant"', '"role" : "assistant"'],
    "P": ['"approval": "final"', '"approval":"execute"'], "V": ['"review": "skipped"', '"review":"stale"'],
    "N": ['"next_turn": "too_late"'], "G": ["defensive", "unit test", "must not", "do not obey"],
    "F": SMP_VOCAB["F"],
}


def _generated(rng, vocab, keys, count):
    """Short texts only (under about 400 characters): the old form is cubic, and
    this test must not be the slow thing it exists to prevent."""
    texts = []
    for _ in range(count):
        parts = [rng.choice(vocab[k]) for k in keys if rng.random() < 0.8]
        parts += [rng.choice(vocab["F"]) for _ in range(rng.randint(0, 6))]
        rng.shuffle(parts)
        texts.append("".join(p + rng.choice([" ", "", "\n", "y" * rng.randint(0, 20)])
                             for p in parts))
    return texts


def test_generated_texts_agree_and_some_of_them_match_for_each_rule():
    rng = random.Random(1108)
    positives = {rule_id: 0 for rule_id in RULES}
    for rule_id, vocab, keys in (("GLS-SMP-023", SMP_VOCAB, "ABCG"),
                                 ("GLS-AW-613", AW_VOCAB, "TRPVNG")):
        for text in _generated(rng, vocab, keys, 400):
            old, new = _agree(rule_id, text)
            assert old == new, (rule_id, text)
            positives[rule_id] += new is not None
    # one total could be met by a single rule, so each rule has its own floor
    for rule_id, count in positives.items():
        assert count >= 40, (
            f"only {count} generated texts matched {rule_id}, so agreement proves little for it")


def _example_texts(node):
    """Every example text under an attack-db `examples` value. The shipped files
    hold a dict of label (malicious, benign) to a list of texts, so the labels
    are keys and never texts."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _example_texts(value)
    elif isinstance(node, list):
        for value in node:
            yield from _example_texts(value)


def test_example_texts_come_from_the_lists_and_not_from_the_labels():
    assert list(_example_texts({"malicious": ["a", "b"], "benign": ["c", {"k": "d"}]})) == [
        "a", "b", "c", "d"]
    assert list(_example_texts({"malicious": [], "benign": []})) == []
    assert list(_example_texts(["x", "y"])) == ["x", "y"]
    assert list(_example_texts("z")) == ["z"]
    assert list(_example_texts(None)) == []


def _corpus_walk(counts):
    for path in sorted((ROOT / "attack-db" / "attacks").rglob("*.json")):
        counts["attack_db_files"] += 1
        for text in _example_texts(json.loads(path.read_text(encoding="utf-8")).get("examples")):
            counts["example_texts"] += 1
            yield text
    for folder in ("tests/fp_real_world_corpus", "tests/fixtures", "gauntlet/corpus"):
        for path in sorted((ROOT / folder).rglob("*")):
            if path.is_file() and path.stat().st_size < 3_000_000:
                counts["corpus_files"] += 1
                yield path.read_text(encoding="utf-8", errors="replace")[:120_000]


def test_the_fixture_corpus_agrees_for_both_rules():
    counts = {"attack_db_files": 0, "example_texts": 0, "corpus_files": 0}
    compared = 0
    for text in _corpus_walk(counts):
        compared += 1
        for rule_id in RULES:
            old, new = _agree(rule_id, text)
            assert old == new, rule_id
    # files read and texts compared are counted apart, so one cannot stand in for the other
    assert counts["attack_db_files"] > 1000, counts
    assert counts["corpus_files"] > 100, counts
    assert compared == counts["example_texts"] + counts["corpus_files"], counts


# ---------------------------------------------------------------------------
# 3. The input that used to run far past the scan budget
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_five_kilobytes_with_the_third_signal_only_at_the_end_scan_quickly(engine):
    """Signals A and B repeat through the text and C appears once, at the very
    end. The prefilter looks at the whole document, so it lets the rule in, and
    every earlier 1200 character window holds A and B but not C: the exact
    case where the interleaved form was cubic, and it ran far past the scan
    budget before the change. The bar is 2 seconds, a wide margin on any runner,
    and it is measured on the same engine in the same process."""
    unit = ("The extractor emits a schema-valid record. The fields were "
            "cross-bound to the wrong actor. " + "q" * 80)
    text = (unit * 100)[:5000 - 6] + " trust"
    assert len(text) == 5000
    engine.scan("warm", channel="message")
    started = time.perf_counter()
    result = engine.scan(text, channel="message")
    elapsed = time.perf_counter() - started
    assert "GLS-SMP-023" in {f["id"] for f in result.findings}, (
        "the rule must still fire on the text it was written for")
    assert elapsed < 2.0, f"a 5 KB scan took {elapsed:.2f}s; the stacked form takes milliseconds"
