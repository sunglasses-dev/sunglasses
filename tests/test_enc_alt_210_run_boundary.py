"""GLS-ENC-ALT-210 branch 2: the run boundary, and why it is safe.

The branch is `(?:[A-Za-z0-9+/]{40,}={0,2}).{0,120}\\b(decode|base64)\\b`. On a
document that CONTAINS the literal -- which is the common case, because
`decode` is what the rule is looking for -- the prefilter correctly cannot skip
it, and the regex engine then tries a match start at every position inside a
long base64-ish run. That is quadratic in the run length: measured 4.14x per
doubling, 74.6 s at 16 KB, and the fit puts 1 MiB near 89 hours.

THE FIX IS A NO-OP ON WHAT IS MATCHED. A start strictly inside a run can never
be the leftmost match, because the run's own start reaches the same end under a
strictly weaker length requirement. `(?<![A-Za-z0-9+/])` says so to the engine,
which collapses the starts from O(bytes) to O(runs).

That was an argument in the backlog for three days. These rows are the
measurement: the span set is identical over the constructed matrix, the shipped
engine's decisions are identical over the same documents, and the cost ratio
per doubling falls from quadratic to linear.
"""
import itertools
import random
import re
import time

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

RULE = "GLS-ENC-ALT-210"
BOUNDARY = r"(?<![A-Za-z0-9+/])"


def _shipped_regex():
    """The rule's regex AS SHIPPED, read from PATTERNS at call time.

    R2/F2 (T10, second reader). Round 1 held two local string literals and
    compared them to each other, tied to the product only by "this lookbehind
    appears somewhere in the rule". Two fossils pass their own differential
    forever, and the guard stayed green while the text sat in any rule in the
    file. So the differential now reads one side out of PATTERNS and DERIVES
    the other by removing the boundary, which is the single edit the change
    made. There is nothing left to drift out of sync with.
    """
    rule = next(p for p in PATTERNS if p["id"] == RULE)
    assert len(rule["regex"]) == 1, (
        f"{RULE} ships {len(rule['regex'])} regexes; this file assumes one")
    return rule["regex"][0]


WITH_BOUNDARY = _shipped_regex()
WITHOUT_BOUNDARY = WITH_BOUNDARY.replace(BOUNDARY, "", 1)


@pytest.fixture(scope="module")
def engine():
    """ONE engine for this file. Building it compiles 1,565 rules and costs
    about ten seconds; the scans themselves are 13 ms and 25 ms. Two rows
    building their own turned a 50 ms measurement into a 23 second test file,
    which is the same lever #176 pulled on the pattern suite."""
    return SunglassesEngine(mechanisms=False)


def _documents(run_lengths, pads=(0, 120, 121),
               words=("decode", "base64", "none"),
               prefixes=("", "=", " ", "+", "/", "z", "==", "\n"),
               eqs=("", "=", "==")):
    """The matrix from BACKLOG_SLOW_RULES_2026-09-13: run length x trailing
    `=` padding x the trigger word at 0/120/121 characters x what precedes the
    run, including the characters that are themselves in the run's class."""
    rnd = random.Random(210)
    alphabet = "ABCdef123+/"
    for length in run_lengths:
        run = "".join(rnd.choice(alphabet) for _ in range(length))
        for pad, word, prefix, eq in itertools.product(
                pads, words, prefixes, eqs):
            tail = ("x" * pad + " " + word) if word != "none" else "x" * pad
            yield prefix + run + eq + tail


def test_the_shipped_rule_carries_the_boundary():
    """The rule this file is about, so a revert cannot leave the rows passing
    against a pattern nobody ships.

    R2/F2: `in` was too weak twice over -- it passed on the text occurring
    ANYWHERE in the rule, including inside a different branch, and it said
    nothing about the unbounded form being gone. Exactly one boundary, and the
    branch it guards present in the form this file measures.
    """
    shipped = _shipped_regex()
    assert shipped.count(BOUNDARY) == 1, (
        f"the run boundary occurs {shipped.count(BOUNDARY)} times in {RULE}; "
        f"this file measures the single-boundary form")
    assert BOUNDARY + r"(?:[A-Za-z0-9+/]{40,}={0,2})" in shipped, (
        "the boundary is in the rule but no longer guards the base64 run")
    assert WITHOUT_BOUNDARY != shipped, "the derivation removed nothing"


def test_the_boundary_changes_no_span():
    """The FULL matrix at the length threshold, a subset above it.

    648 documents at 39/40/41 -- the boundary of the `{40,}` requirement, where
    every combination is cheap (3 lengths x 3 paddings x 3 trigger words x 8
    preceding characters x 3 trailing suffixes) -- plus 64 at 512 (2 x 2 x 8 x
    2), which is where a long run would show a difference if one existed.

    THE SIZES ARE CHOSEN BY WHAT THE UNBOUNDED FORM COSTS, not by taste.
    Proving equivalence means running the quadratic, so the full matrix at 512
    is 19 seconds of a 21 second file and 4096 is minutes. The subset keeps all
    eight preceding characters -- including `+`, `/` and an alphanumeric, the
    ones the lookbehind is actually about -- and drops only redundant
    combinations of padding and trailing `=`.
    """
    old = re.compile(WITHOUT_BOUNDARY, re.I | re.S)
    new = re.compile(WITH_BOUNDARY, re.I | re.S)
    documents = list(_documents((39, 40, 41)))
    documents += list(_documents((512,), pads=(0, 121), words=("decode", "none"),
                                 eqs=("", "==")))
    assert len(documents) == 648 + 64, len(documents)
    for document in documents:
        assert ([(m.start(), m.end()) for m in old.finditer(document)]
                == [(m.start(), m.end()) for m in new.finditer(document)])


@pytest.fixture(scope="module")
def unbounded_engine():
    """The SAME engine with ONE edit: the boundary removed from this rule.

    R2/F1 (T10, second reader). Round 1 compared the shipped engine against the
    number 402 in its own docstring, so the row was a regression pin wearing a
    differential's name: a mis-measured 402 would have been pinned forever and
    nothing would ever have caught it. Both sides are now EXECUTED over the
    same corpus. Costs a second build (~10 s); at these run lengths the
    quadratic is not yet expensive, which is exactly why the equivalence
    corpus lives at 39/40/41 and not at 4096.
    """
    patched = [dict(p, regex=[WITHOUT_BOUNDARY]) if p["id"] == RULE else p
               for p in PATTERNS]
    assert sum(1 for p in patched
               if p.get("regex") == [WITHOUT_BOUNDARY]) == 1
    return SunglassesEngine(patterns=patched, mechanisms=False)


def _named(engine, document):
    return {f.get("rule_id") or f.get("id")
            for f in engine.scan(document, channel="file").findings}


def test_the_shipped_engine_decides_the_same_way(engine, unbounded_engine):
    """Spans are the mechanism; DECISIONS are what a user gets.

    Both engines run. Not just "does ENC-ALT-210 still fire": the whole set of
    rule ids per document, and the decision itself, because a change to one
    rule's span can move what another rule sees.
    """
    documents = list(_documents((39, 40, 41)))
    assert len(documents) == 648, len(documents)
    naming = 0
    for document in documents:
        before = unbounded_engine.scan(document, channel="file")
        after = engine.scan(document, channel="file")
        assert _named(unbounded_engine, document) == _named(engine, document), (
            f"the rule set changed for {document[:60]!r}...")
        assert before.decision == after.decision, (
            f"decision {before.decision} -> {after.decision} for "
            f"{document[:60]!r}...")
        naming += RULE in _named(engine, document)
    assert naming == 402, (
        f"{naming} of {len(documents)} documents name {RULE}; 402 is the count "
        f"recorded when this row was written, and it is now checkable -- both "
        f"branches ran here, so a differing corpus is the only way to move it")


@pytest.mark.parametrize("small,large", [(8000, 16000)])
def test_the_cost_is_linear_in_the_run(small, large, engine):
    """A RATIO, never seconds: seconds belong to whatever machine ran them.

    Doubling the run doubles the work when the boundary is there and
    QUADRUPLES it when it is not -- measured 2.03x against 4.14x. The gate is
    3.0, which no linear curve reaches and no quadratic one avoids, so a slow
    machine cannot fail it and a reintroduced quadratic cannot pass it.
    """
    def seconds(n):
        document = "decode " + "A" * n
        best = None
        for _ in range(3):
            start = time.perf_counter()
            engine.scan(document, channel="file")
            elapsed = time.perf_counter() - start
            best = elapsed if best is None else min(best, elapsed)
        return best

    ratio = seconds(large) / seconds(small)
    assert ratio < 3.0, (
        f"doubling the run multiplied the cost by {ratio:.2f}; the bounded "
        f"branch measures about 2.0 and the unbounded one about 4.1, so this "
        f"looks like the quadratic came back")
