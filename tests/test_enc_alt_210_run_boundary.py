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
WITHOUT_BOUNDARY = r'((?:[A-Za-z0-9+/]{40,}={0,2}).{0,120}\b(decode|base64)\b)'
WITH_BOUNDARY = (r'((?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{40,}={0,2})'
                 r'.{0,120}\b(decode|base64)\b)')


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
    against a pattern nobody ships."""
    rule = next(p for p in PATTERNS if p["id"] == RULE)
    assert any("(?<![A-Za-z0-9+/])" in r for r in rule["regex"]), (
        "the run boundary is not in the shipped rule")


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


def test_the_shipped_engine_decides_the_same_way(engine):
    """Spans are the mechanism; DECISIONS are what a user gets. Run the real
    engine over the same corpus and require the rule ids to match what the
    unbounded branch produced -- recorded here as the count, because the
    interesting failure is the rule going quiet, not a reordering."""
    documents = list(_documents((39, 40, 41)))
    naming = sum(1 for d in documents
                 if RULE in {f.get("rule_id") or f.get("id")
                             for f in engine.scan(d, channel="file").findings})
    assert len(documents) == 648, len(documents)
    assert naming == 402, (
        f"{naming} of {len(documents)} documents name {RULE}; the unbounded "
        f"branch named 402 of the same documents, measured before the change")


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
