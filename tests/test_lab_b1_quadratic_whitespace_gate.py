"""Lab finding B1 gate: no pattern regex may cost more than linear time on a
whitespace run.

Written as the CI gate that would have caught lab finding B1 (GLS-IP-006 and
GLS-EX-030 quadratic on a run of newlines, bounded on main by the engine's
lead-in mode from #340). Two parts, both over every regex entry the engine
loads (carriers and mechanisms), one test per entry so a known slow entry is a
strict xfail that trips the day it is fixed, and a NEW slow entry fails on its
own id.

1. Static shape check (instant, runs in the fast suite). Two shapes are
   quadratic on a run of whitespace and are never needed:
     a. a newline-admitting atom followed by an unbounded whitespace quantifier
        (`[\\n...]\\s*`, `\\n\\s+`): every newline in the run is a start, and each
        start walks the rest of the run before giving it back.
     b. two unbounded whitespace quantifiers with nothing, or only an optional
        comma, between them (`\\s*,?\\s*`): a run of N characters is split
        N ways before the next token fails.
   The fix for either is to let only one quantifier be unbounded and to stop
   optional whitespace after a delimiter at the next newline (`[^\\S\\n]*`),
   because the last newline of a run is itself a delimiter.
   An entry whose whole source is in the engine's LEADIN_SOURCES is judged on
   the twin the engine searches with (LEADIN_OLD replaced by LEADIN_FAST once),
   because that twin, not the stored source, is what walks the text. Exact
   membership only, the same rule the engine applies.

2. Timed probe (`slow` marker, needs SIGALRM, main thread). Each entry is
   evaluated the way the engine evaluates it (`_eval_regex` with the entry's
   mode) on whitespace runs of 16,000 characters, seeded with the literals
   the prefilter requires (joined, and each one alone right before the run, so
   a shape that is quadratic from a single start is reached), under a 0.5 s
   alarm per probe. Linear entries take milliseconds at this size.

KNOWN_SHAPE and KNOWN_SLOW list the entries that are red today, each a strict
xfail: fixing one without removing it from the list fails the suite, which is
the ratchet. Never widen the cap or the lists to make an entry green.
"""
import re
import signal
import threading
import time

import pytest

from sunglasses.engine import SunglassesEngine

UNBOUNDED_WS = r"\\s(?:[*+]|\{\d*,\})"
NEWLINE_ATOM = r"(?:\\n|\\r|\[[^\]]*\\n[^\]]*\])"
SHAPES = (
    ("newline atom then unbounded whitespace", re.compile(NEWLINE_ATOM + UNBOUNDED_WS)),
    ("two unbounded whitespace quantifiers", re.compile(UNBOUNDED_WS + r"(?:,\?)?" + UNBOUNDED_WS)),
)

PROBE_LEN = 16_000
CAP_S = 0.5

ENGINE = SunglassesEngine()

# Entries that carry a quadratic shape in their source today (lab finding B1,
# section 4b). Each is open work; the fix of the same family is noted.
KNOWN_SHAPE = {
    ("GLS-EX-011", 0): r"\]\s*\n\s*\[ -> \][^\S\n]*\n\s*\[",
    ("GLS-EX-012", 0): r"\]\s*\n\s*\[ -> \][^\S\n]*\n\s*\[",
    ("GLS-APIP-012", 0): r"spec:\s*\n\s* -> spec:[^\S\n]*\n\s*",
    ("GLS-CICD-006", 0): r"metadata:\s*\n\s* -> metadata:[^\S\n]*\n\s*",
    ("GLS-DFP-001", 0): r"system\s*,?\s*developer -> system(?:\s*,)?\s*developer (flat today, literal follows)",
    ("GLS-DFP-007", 0): r"system\s*,?\s*developer -> system(?:\s*,)?\s*developer (flat today, literal follows)",
    ("GLS-DFP-073", 0): r"runs\s*:\s*(?:\n\s*)?using -> runs\s*:[^\S\n]*(?:\n\s*)?using",
    ("GLS-DFP-069", 0): r"channels\s*:\s*\n\s*-\s -> channels\s*:[^\S\n]*\n\s*-\s",
}

# Entries over the 0.5 s cap at 16,000 characters on this machine today, the
# way the engine runs them. Measured list, see the PR for the receipt.
KNOWN_SLOW = {
    ("GLS-AW-001", 0): "critical, read/fetch/crawl/scrape then a whitespace run; fix of the B1 family",
    ("GLS-SC-018", 0): "double quantifier under a bounded .{0,120}; fix of the B1 family",
    ("GLS-CF-251", 0): "decision then a run; fix of the B1 family",
    ("GLS-EX-011", 0): "see KNOWN_SHAPE",
    ("GLS-EX-012", 0): "see KNOWN_SHAPE",
    ("GLS-APIP-012", 0): "see KNOWN_SHAPE",
    ("GLS-CICD-006", 0): "see KNOWN_SHAPE",
    ("GLS-DFP-073", 0): "see KNOWN_SHAPE",
    ("GLS-DFP-069", 0): "see KNOWN_SHAPE",
    ("GLS-AW-713", 0): "guarded predicate, own design needed",
    ("GLS-CICD-004", 0): "linear with a large per-byte constant; needs a per-rule budget",
}


def _static_subject(source: str) -> str:
    if source in ENGINE.LEADIN_SOURCES:
        return source.replace(ENGINE.LEADIN_OLD, ENGINE.LEADIN_FAST, 1)
    return source


def _static_params():
    for pattern in ENGINE._patterns:
        for index, source in enumerate(pattern.get("regex", [])):
            key = (pattern["id"], index)
            marks = ()
            if key in KNOWN_SHAPE:
                marks = pytest.mark.xfail(strict=True, reason=f"known shape, fix: {KNOWN_SHAPE[key]}")
            yield pytest.param(pattern["id"], index, source, id=f"{key[0]}-{index}", marks=marks)


@pytest.mark.parametrize("rule_id,index,source", list(_static_params()))
def test_regex_entry_has_no_quadratic_whitespace_shape(rule_id, index, source):
    subject = _static_subject(source)
    hits = []
    for name, shape in SHAPES:
        m = shape.search(subject)
        if m:
            hits.append(f"{name}: ...{subject[max(0, m.start() - 12):m.end() + 12]}...")
    assert not hits, f"{rule_id} #{index}: quadratic whitespace shape:\n" + "\n".join(hits)


def test_the_known_lists_name_only_entries_that_exist():
    live = {(p["id"], i) for p in ENGINE._patterns for i, _ in enumerate(p.get("regex", []))}
    assert set(KNOWN_SHAPE) <= live, set(KNOWN_SHAPE) - live
    assert set(KNOWN_SLOW) <= live, set(KNOWN_SLOW) - live


def test_the_six_leadin_sources_are_judged_on_the_twin():
    # The engine bounds exactly these; the gate must see them through the twin.
    six = {(p["id"], i) for p in ENGINE._patterns for i, r in enumerate(p.get("regex", []))
           if r in ENGINE.LEADIN_SOURCES}
    assert six == {("GLS-IP-006", 0), ("GLS-IP-006", 1), ("GLS-IP-006", 2), ("GLS-IP-006", 3),
                   ("GLS-EX-030", 0), ("GLS-EX-030", 1)}
    for p in ENGINE._patterns:
        for r in p.get("regex", []):
            if r in ENGINE.LEADIN_SOURCES:
                assert SHAPES[0][1].search(r), "the stored source still carries the shape"
                assert not SHAPES[0][1].search(_static_subject(r)), "the twin must not"


class _Budget(Exception):
    pass


def _timed(fn, cap):
    """Run fn under a SIGALRM budget. Returns (seconds, over_budget)."""
    def handler(signum, frame):
        raise _Budget()
    old = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, cap)
    t0 = time.perf_counter()
    over = False
    try:
        try:
            fn()
        except _Budget:
            over = True
        seconds = time.perf_counter() - t0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
    return seconds, over


def _seeds(requirement):
    """Seeds for the timed probe. The joined seed (one literal per CNF clause)
    makes the rule findable; each single literal (longest eight) placed right
    before the run catches shapes that are quadratic from ONE start, such as
    `key:\\s*\\n\\s*value`, which only hurt when the run follows that literal."""
    joined = " ".join(sorted(clause, key=len, reverse=True)[0]
                      for clause in requirement if clause)
    singles = sorted({lit for clause in requirement for lit in clause}, key=len, reverse=True)[:8]
    seeds = [joined + " " if joined else ""]
    seeds += [lit for lit in singles if lit + " " != seeds[0]]
    return seeds


def _probe_texts(seeds):
    joined = seeds[0]
    unit_nl = joined + "\n"
    unit_sp = joined + " "
    texts = {
        "seed+newline repeated": (unit_nl * (PROBE_LEN // len(unit_nl) + 1))[:PROBE_LEN],
        "seed+space repeated": (unit_sp * (PROBE_LEN // len(unit_sp) + 1))[:PROBE_LEN],
    }
    for seed in seeds:
        texts[f"{seed!r}+newline run"] = seed + "\n" * PROBE_LEN
        texts[f"{seed!r}+space run"] = seed + " " * PROBE_LEN
    return texts


def _timed_params():
    for pattern, compiled in ENGINE._regex_patterns:
        for index, (mode, rx, guards) in enumerate(compiled):
            key = (pattern["id"], index)
            marks = ()
            if key in KNOWN_SLOW:
                marks = pytest.mark.xfail(strict=True, reason=f"known slow: {KNOWN_SLOW[key]}")
            yield pytest.param(pattern["id"], index, mode, rx, guards,
                               id=f"{key[0]}-{index}-{mode}", marks=marks)


@pytest.mark.slow
@pytest.mark.parametrize("rule_id,index,mode,rx,guards", list(_timed_params()))
def test_regex_entry_is_linear_on_whitespace_runs(rule_id, index, mode, rx, guards):
    if not hasattr(signal, "SIGALRM"):
        pytest.skip("the per-probe budget needs SIGALRM")
    if threading.current_thread() is not threading.main_thread():
        pytest.skip("the per-probe budget needs the main thread")
    slow = []
    seeds = _seeds(ENGINE._regex_requirement.get(id(rx), ()))
    for shape, text in _probe_texts(seeds).items():
        seconds, over = _timed(lambda: ENGINE._eval_regex(mode, rx, guards, text), CAP_S)
        if over or seconds > CAP_S:
            slow.append(f"on {shape}: {'over' if over else ''} {seconds:.2f} s")
    assert not slow, (f"{rule_id} #{index} ({mode}) exceeded {CAP_S} s at "
                      f"{PROBE_LEN} characters:\n" + "\n".join(slow))
