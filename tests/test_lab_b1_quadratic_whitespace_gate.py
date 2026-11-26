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
     b. two unbounded whitespace quantifiers with nothing, or only one optional
        token, between them (`\\s*,?\\s*`, `\\s*:?\\s*`, `\\s*["']?\\s*`,
        `\\s+(?:schema)?\\s*`, `\\s*[,:.]?\\s+`): when the token is absent, a
        run of N characters is split N ways before the next token fails.
   The fix for either is to let only one quantifier be unbounded and to stop
   optional whitespace after a delimiter at the next newline (`[^\\S\\n]*`),
   because the last newline of a run is itself a delimiter. For (b) the
   optional token brings its own trailing blanks (`\\s*(?::\\s*)?`), or, when a
   blank is required after it, the blanks before it (`(?:\\s*[,:.])?\\s+`).
   An entry whose shape (b) sits only where the engine bounds the run (the
   positive core of a windowed or guarded predicate, matched per
   co-occurrence window) is listed in BOUNDED_SHAPE with its reason; the
   test checks that the engine still runs it that way, and checks shape (b)
   in its guards, which the engine evaluates on the whole document.
   An entry whose whole source is in the engine's LEADIN_SOURCES is judged on
   the twin the engine searches with (LEADIN_OLD replaced by LEADIN_FAST once),
   because that twin, not the stored source, is what walks the text. Exact
   membership only, the same rule the engine applies.

2. Timed probe (`slow` marker, needs SIGALRM, main thread). Each entry is
   evaluated the way the engine evaluates it (`_eval_regex` with the entry's
   mode) on whitespace runs of PROBE_LEN characters, seeded with the literals
   the prefilter requires (joined, and each one alone right before the run, so
   a shape that is quadratic from a single start is reached), under a CAP_S
   alarm per probe. A run that follows an opening bracket is probed too
   (`seed(` then the run): a blank run split between `\\(\\s*` and a lazy class
   after it, as GLS-SQLFS-001 had, is only reached when a bracket comes first. The same
   goes for a run after a keyword inside the bracket (`seed(BULK` then the run).
   The prefilter literals are not always the text right before a shape, so
   every entry that carries two unbounded whitespace quantifiers with at most
   one optional token between them is also probed from the shape itself: the
   representative text the regex reads up to the first quantifier (built from
   the parsed regex), then the run.
   A linear entry finishes far inside the cap.

KNOWN_SHAPE lists the shape entries that are red today, each a strict xfail:
fixing one without removing it from the list fails the suite, which is the
ratchet. KNOWN_SLOW lists the entries whose run time grows faster than the
input; their ratchet is the growth test, which compares the run time at two
input sizes and so does not depend on how fast the machine is (a wall clock
limit alone turned the smallest margin entry red on a fast runner). Never
widen the cap or the lists to make an entry green.
"""
import re
import signal
import threading
import time

try:  # Python 3.11+
    import re._constants as _sre_c
    import re._parser as _sre_parse
except ImportError:  # Python 3.9 and 3.10
    import sre_constants as _sre_c
    import sre_parse as _sre_parse

import pytest

from sunglasses.engine import SunglassesEngine

UNBOUNDED_WS = r"\\s(?:[*+]|\{\d*,\})"
NEWLINE_ATOM = r"(?:\\n|\\r|\[[^\]]*\\n[^\]]*\])"
# One optional token: a class, one (escaped) character, or a group (with at most
# one level of groups inside it), followed by `?`.
OPTIONAL_TOKEN = r"(?:\[[^\]]*\]\?|\\?.\?|\(\?:(?:[^()]|\([^()]*\))*\)\?)"
# Shape (a) also holds when the atom sits in a group that closes right before the whitespace: a
# closing paren after it, an alternative after it inside the group, or an alternative before it
# (`(?:^|[.\n])\s*`, `(?:\n|;)\s*`, `(?:;|\n)\s*`). A class in an alternative may hold parens.
GROUP_ALT = r"(?:\[[^\]]*\]|[^()\[\]])*"
NEWLINE_THEN_WS = re.compile("|".join((
    NEWLINE_ATOM + UNBOUNDED_WS,
    NEWLINE_ATOM + r"\)+" + UNBOUNDED_WS,
    NEWLINE_ATOM + r"\|" + GROUP_ALT + r"\)+" + UNBOUNDED_WS,
    r"\|" + NEWLINE_ATOM + r"\)+" + UNBOUNDED_WS,
    GROUP_ALT + r"\|" + NEWLINE_ATOM + r"\)+" + UNBOUNDED_WS,
)))
# Under a multiline flag `^` starts every line, so a line start then unbounded whitespace is the
# same walk as a newline atom then unbounded whitespace.
LINE_START_THEN_WS = re.compile(
    r"(?s)^(?=\(\?[a-z]*m).*?(?:\^" + UNBOUNDED_WS + r"|\^\|" + GROUP_ALT + r"\)+" + UNBOUNDED_WS
    + r"|\|\^\)+" + UNBOUNDED_WS + ")")
SHAPES = (
    ("newline atom then unbounded whitespace", NEWLINE_THEN_WS),
    ("two unbounded whitespace quantifiers",
     re.compile(UNBOUNDED_WS + OPTIONAL_TOKEN + "?" + UNBOUNDED_WS)),
    ("line start then unbounded whitespace under a multiline flag", LINE_START_THEN_WS),
)

PROBE_LEN = 16_000
CAP_S = 0.5

# Growth test for KNOWN_SLOW. A probe is run at GROW_START characters, then at double
# the size, and so on. Linear work about doubles per step, quadratic work about
# quadruples, so GROW_RATIO sits between the two. A step counts only when its smaller run
# took at least GROW_MIN_S (below that the clock noise is a large part of the time), and a
# family of probes stops once a run is over GROW_STOP_S, so the test stays short on a
# slow entry and cheap on a fast machine.
GROW_START = 250
GROW_MIN_S = 0.004
GROW_STOP_S = 0.25
GROW_CAP_S = 1.0
GROW_RATIO = 3.0
assert GROW_CAP_S / GROW_STOP_S >= GROW_RATIO, "a run over the budget must mean growth over the ratio"

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
    # Found when shape (b) was widened from an optional comma to one optional token (lab
    # finding H5). Run by the engine on the whole text, so not bounded by a window.
    # The two anchored entries are searched only near their anchor words, but when those
    # words are dense the engine searches the whole text: measured 5.5 s on `<`, a
    # 16,000-blank run and dense anchor words after it. The probe does not build that text.
    ("GLS-PI-INFO-API", 0): r"<\s*/?\s*(?:information -> <\s*(?:/\s*)?(?:information (anchored)",
    ("GLS-PI-INFO-API", 1): r"<\s*/?\s*(?:information -> <\s*(?:/\s*)?(?:information (anchored)",
    ("GLS-AW-013", 0): r"(?:^|\n)\s*-?\s*(?:run -> \s*(?:-\s*)?(?:run, plus the newline atom before it (shape a)",
    ("GLS-JBE-003", 1): r"\s*(?:class|...|project)?\s*[—,:\-] -> \s*(?:(?:class|...|project)\s*)?[—,:\-]",
    ("GLS-AW-101", 0): r"\s+(?:to)?\s*(?:same -> \s+(?:to\s*)?(?:same",
    ("GLS-AW-131", 0): r"\s*(?:[,.;:-]|so)?\s*(?:skip -> \s*(?:(?:[,.;:-]|so)\s*)?(?:skip",
    ("GLS-AW-141", 0): r"\s*(?:[,.;:-]|so)?\s*(?:use -> \s*(?:(?:[,.;:-]|so)\s*)?(?:use",
    ("GLS-AW-142", 0): r"\s*(?:[,.;:-]|so)?\s*(?:skip -> \s*(?:(?:[,.;:-]|so)\s*)?(?:skip",
    ("GLS-AW-154", 0): r"\s+(?:status|authority)?\s*(?:overshadow -> \s+(?:(?:status|authority)\s*)?(?:overshadow",
    ("GLS-CF-250", 0): r"\s+(?:to|so\s+that|in\s+order\s+to)?\s*(?:truncate -> \s+(?:(?:to|...)\s*)?(?:truncate",
    ("GLS-MP-005", 0): r"\s*[.,]?\s+(?:instruction -> (?:\s*[.,])?\s+(?:instruction",
    ("GLS-JBE-002", 0): r"\s+(?:you(?:'re|\s+are)|to\s+be)?\s*my -> \s+(?:(?:you(?:'re|\s+are)|to\s+be)\s*)?my",
    ("GLS-MCP-018", 0): r"\s*(?::|\.)?\s*\{? and \s*[\"']?\s*(?:data -> one quantifier per run, as above",
}

# Entries over the cap at the probe length on this machine today, the
# way the engine runs them. Measured list, see the PR for the receipt.
KNOWN_SLOW = {
    # Measured on main ef825e92b273 (Oct 8 2026) with the lab round-1 gate: five entries went
    # over the cap. GLS-AW-001 was made linear in #354; GLS-SC-018, GLS-CF-251 and GLS-AW-713
    # were made linear with lab finding H5 (one quantifier per whitespace run).
    # The six KNOWN_SHAPE sources did not, because the engine judges them on the twin.
    # Found by the bracket probe row (a run of blanks right after an opening bracket): over the cap
    # at the probe size, growing with the square of the run. `\(\s*['"]?[^)]*\b` splits
    # the run between `\s*` and `[^)]*`, the same shape GLS-SQLFS-001 had. Fix like SQLFS-001.
    ("GLS-SSRF-008", 0): "blank run after the bracket split between \\s* and [^)]*; 3 probes over (plain)",
    # Found by the shape-lead probe row (the text the regex reads up to a shape (b), then a run),
    # lab finding H5. Each is in KNOWN_SHAPE; the fix is noted there. Times are 4,000 then
    # 16,000 newlines after the lead, one process, on the machine that wrote this list.
    ("GLS-AW-013", 0): "newline then a run; 0.5 s at 500, 3.1 s at 1,000, 15 s at 2,000 newlines (plain)",
    ("GLS-MCP-018", 0): "_meta then a run; 0.11 s at 500, 3.3 s at 2,000, 14.5 s at 4,000; 6 probes over (plain)",
    ("GLS-JBE-003", 1): "creative writing then a run; 0.06 s / 0.92 s; 2 probes over (plain)",
    ("GLS-AW-101", 0): "referring then a run; 0.19 s / 3.1 s; 2 probes over (plain)",
    ("GLS-AW-131", 0): "exhausted then a run; 0.21 s / 3.4 s; 2 probes over (plain)",
    ("GLS-AW-141", 0): "down then a run; 0.14 s / 2.2 s; 2 probes over (plain)",
    ("GLS-AW-142", 0): "exhausted then a run; 0.19 s / 3.1 s; 2 probes over (plain)",
    ("GLS-AW-154", 0): "reply then a run; 0.28 s / 4.5 s; 2 probes over (plain)",
    ("GLS-CF-250", 0): "window then a run; 0.17 s / 2.6 s; 2 probes over (plain)",
    ("GLS-MP-005", 0): "forever then a run; 0.22 s / 3.4 s; 2 probes over (plain)",
    ("GLS-JBE-002", 0): "pretend then a run; 0.045 s / 0.72 s; 2 probes over (plain)",
}

# Entries over the cap because the work per byte is large, not because it grows faster than
# the input. The growth test does not apply to them. Not strict: a faster machine may bring
# one inside the cap, and that says nothing about the entry.
KNOWN_SLOW_HEAVY = {
}

# Entries whose shape (b) sits only in the positive core of a guarded predicate,
# which the engine matches per co-occurrence window (COOCCUR_WINDOW characters),
# so a run inside it is bounded by the window. The guards, which the engine checks
# on the whole text, are still held to shape (b). The time is the slowest probe
# row, shape-lead rows included, on the machine that wrote this list.
BOUNDED_SHAPE = {
    ("GLS-SMP-016", 0): r"(?:agentic)?\s*(?:research|...)?\s*(?:agents? in the windowed core; 23 ms",
    ("GLS-BMP-004", 0): r"\s+(?:build|...)?\s*(?:guidance in the windowed core; 4 ms",
    ("GLS-BMP-007", 0): r"\s+(?:build|...)?\s*(?:guidance in the windowed core; 4 ms",
    ("GLS-SCAP-004", 0): r"signed\s*[:.]?\s*_type in the windowed core; 6 ms",
    ("GLS-DFP-028", 0): r"patch\s*['\"]?\s*: and filter\s*['\"]?\s*: in the windowed core; 4 ms",
    ("GLS-DFP-029", 0): r"ad\s*(?:quality|fraud)?\s*scanner in the windowed core; 4 ms",
    ("GLS-DFP-058", 0): r"automated\s+(?:test|...)?\s*(?:review in the windowed core; 3 ms",
    ("GLS-DFP-062", 0): r"automated\s+(?:build|...)?\s*(?:review in the windowed core; 3 ms",
    ("GLS-DFP-071", 0): r"\s+(?:release|...)?\s*(?:policy in the windowed core; 9 ms",
    ("GLS-DFP-072", 0): r"\s+(?:any|all|your|the)?\s*(?:project in the windowed core; 2 ms",
    ("GLS-DFP-079", 0): r"automated\s+(?:mail|...)?\s*(?:review in the windowed core; 4 ms",
    ("GLS-DFP-087", 0): r"automated\s+(?:browser|...)?\s*(?:review in the windowed core; 3 ms",
    ("GLS-MCP-033", 0): r"treat\s+(?:this|the)?\s*(?:catalog in the windowed core; 1 ms",
    ("GLS-MCP-055", 0): r"audience\b\s*[\"']?\s*[:=] and priority\b\s*[\"']?\s*[:=] in the windowed core; 0.4 ms",
    ("GLS-DFP-111", 0): r"\s+(?:approval|...)?\s*(?:policy in the windowed core; 5 ms",
    ("GLS-DFP-112", 0): r"\s+(?:approval|...)?\s*(?:policy in the windowed core; 5 ms",
    ("GLS-DFP-136", 0): r"json\s*-?\s*rpc in the windowed core; 4 ms",
    ("GLS-AW-601", 0): r"qa\s*\+?\s*fixer in the windowed core; 4 ms",
    ("GLS-ABX-016", 0): r"item\s*/?\s*read in the windowed core; 5 ms",
    ("GLS-AB-009", 0): r"auth\w*\s*[\"']?\s*: in the windowed core; 0.5 ms",
    ("GLS-DKS-002", 0): r"score\s*[:=]?\s*10 in the windowed core; 1 ms",
    ("GLS-MR-032", 0): r"referenced\s*[_-]?\s*(?:dataset and allowed\s*[_-]?\s*datasets in the windowed core; 0.6 ms",
    # A newline inside a group or a class, and a line start under a multiline flag, count as a newline atom. The newline then a run sits in the positive
    # core of a guarded predicate, which the engine matches per co-occurrence window; the growth
    # probes show no growth on the engine's run.
    ("GLS-DFP-040", 0): r"(?:^|\n)\s*annotations:\s*\n in the guarded core, matched per 1,200 character window; no growth on the engine's run",
    ("GLS-DFP-055", 0): r"(?:^|[\n\r])\s*\[(?:Unit|Service|Timer|Socket|Install)\] in the guarded core, matched per 1,200 character window; no growth on the engine's run",
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


def _bounded_subjects(rule_id, index):
    """For an entry in BOUNDED_SHAPE: the sources the engine runs on the whole
    document (the guards of a guarded entry, nothing for a windowed one), or
    None when the engine no longer runs the entry in a windowed mode."""
    compiled = ENGINE._compiled_by_id.get(rule_id, ())
    if index >= len(compiled):
        return None
    mode, _rx, guards = compiled[index]
    if mode == "windowed":
        return []
    if mode == "guarded":
        return [g.pattern for g in guards]
    return None


@pytest.mark.parametrize("rule_id,index,source", list(_static_params()))
def test_regex_entry_has_no_quadratic_whitespace_shape(rule_id, index, source):
    subject = _static_subject(source)
    hits = []
    for name, shape in SHAPES:
        m = shape.search(subject)
        if m and (rule_id, index) in BOUNDED_SHAPE:
            unbounded = _bounded_subjects(rule_id, index)
            assert unbounded is not None, (
                f"{rule_id} #{index} is in BOUNDED_SHAPE but the engine no longer runs it "
                f"per co-occurrence window")
            m = next(filter(None, (shape.search(g) for g in unbounded)), None)
            if m is None:
                continue
            subject = m.string
        if m:
            hits.append(f"{name}: ...{subject[max(0, m.start() - 12):m.end() + 12]}...")
    assert not hits, f"{rule_id} #{index}: quadratic whitespace shape:\n" + "\n".join(hits)


def _static_flagged(source):
    return any(shape.search(source) for name, shape in SHAPES if shape is not SHAPES[1][1])


# Sources written out as strings, so the check is tested without any engine or stack head.
# The first is a persona-order rule whose line-start delimiter group closes right before the
# unbounded whitespace: 0.32, 1.28, 5.08 and 20.4 s on 2,000, 4,000, 8,000 and 16,000 newlines.
STATIC_FLAGGED = {
    "group_closes_before_ws": (
        '(?im)(?:(?:^|[.!?:;\\n>\\"\'\\u201c\\u2018(\\[*\\u2022-])\\s*(?:(?:please|now)\\s+){0,2}'
        '|,\\s*(?:(?:please|now)\\s+){1,2})(?:act as an?)\\b'),
    "line_start_or_newline": r"(?:^|\n)\s*run\b",
    "newline_in_a_group": r"(\n)\s+run\b",
    "class_in_a_group": r"(?:[.\n])\s*run\b",
    "newline_then_alternative": r"(?:\n|;)\s*run\b",
    "alternative_then_newline": r"(?:;|\n)\s*run\b",
    "class_with_parens_then_alternative": r"(?:[(\n]|;)\s*run\b",
    "line_start_under_multiline": r"(?im)(?:^|[.!?])\s*run\b",
    "line_start_alone_under_multiline": r"(?m)^\s*run\b",
    "line_start_then_alternative_under_multiline": r"(?m)(?:^|;)\s*run\b",
}
STATIC_CLEAN = {
    "horizontal_space_after_the_delimiter": r"(?im)(?:^|[.!?:;\n])[^\S\n]*run\b",
    "newline_in_a_group_then_literal": r"(?:\n)run\b",
    "line_start_without_a_multiline_flag": r"(?i)(?:^|[.!?])\s*run\b",
    "a_run_of_blanks_after_a_word": r"run\s*(?:now|please)\b",
    "alternatives_outside_the_group": r"(?:\n)|\s*run\b",
}


@pytest.mark.parametrize("name", sorted(STATIC_FLAGGED))
def test_the_static_check_flags_the_quadratic_source(name):
    assert _static_flagged(STATIC_FLAGGED[name]), name


@pytest.mark.parametrize("name", sorted(STATIC_CLEAN))
def test_the_static_check_leaves_the_linear_source_alone(name):
    assert not _static_flagged(STATIC_CLEAN[name]), name


@pytest.mark.parametrize("key", sorted(BOUNDED_SHAPE), ids=lambda k: f"{k[0]}-{k[1]}")
def test_each_bounded_entry_still_carries_the_shape(key):
    # Fixing one without removing it from BOUNDED_SHAPE fails here, so the list stays true.
    source = next(p["regex"][key[1]] for p in ENGINE._patterns if p["id"] == key[0])
    assert any(shape.search(source) for _name, shape in SHAPES), f"{key} no longer carries a shape; remove it"


def test_the_known_lists_name_only_entries_that_exist():
    live = {(p["id"], i) for p in ENGINE._patterns for i, _ in enumerate(p.get("regex", []))}
    assert set(KNOWN_SHAPE) <= live, set(KNOWN_SHAPE) - live
    assert set(KNOWN_SLOW) <= live, set(KNOWN_SLOW) - live
    assert set(KNOWN_SLOW_HEAVY) <= live, set(KNOWN_SLOW_HEAVY) - live
    assert not set(KNOWN_SLOW) & set(KNOWN_SLOW_HEAVY)
    assert set(BOUNDED_SHAPE) <= live, set(BOUNDED_SHAPE) - live
    assert not set(BOUNDED_SHAPE) & set(KNOWN_SHAPE)


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


def _best_timed(fn, cap, tries=3):
    """The best of up to `tries` runs of _timed, stopping at the first one inside `cap`.
    A busy machine only adds time, so one slow run says little; a quadratic entry is over
    the cap on every try."""
    best = None
    for _ in range(tries):
        seconds, over = _timed(fn, cap)
        if best is None or (over, seconds) < (best[1], best[0]):
            best = (seconds, over)
        if not over and seconds <= cap:
            break
    return best


def _min_timed(fn, cap, tries=3):
    """The fastest of `tries` runs of _timed, always all of them, so a step of the growth test
    never rests on one run. A run over `cap` ends it at once and is reported as over."""
    best = None
    for _ in range(tries):
        seconds, over = _timed(fn, cap)
        if over:
            return seconds, True
        if best is None or seconds < best:
            best = seconds
    return best, False


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


def _probe_texts(seeds, n=PROBE_LEN):
    joined = seeds[0]
    unit_nl = joined + "\n"
    unit_sp = joined + " "
    texts = {
        "seed+newline repeated": (unit_nl * (n // len(unit_nl) + 1))[:n],
        "seed+space repeated": (unit_sp * (n // len(unit_sp) + 1))[:n],
    }
    for seed in seeds:
        texts[f"{seed!r}+newline run"] = seed + "\n" * n
        texts[f"{seed!r}+space run"] = seed + " " * n
        texts[f"{seed!r}+bracket then space run"] = seed + "(" + " " * n
        texts[f"{seed!r}+bulk then space run"] = seed + "(BULK" + " " * n
    return texts


_SPACE = (_sre_c.IN, [(_sre_c.CATEGORY, _sre_c.CATEGORY_SPACE)])
_REPEATS = (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT)


def _unbounded_space(node):
    op, av = node
    return op in _REPEATS and av[1] == _sre_c.MAXREPEAT and list(av[2]) == [_SPACE]


def _optional(node):
    op, av = node
    return op in _REPEATS and av[0] == 0 and av[1] == 1


def _class_char(items):
    """One character the class accepts."""
    negate = bool(items) and items[0][0] is _sre_c.NEGATE

    def accepts(ch):
        for op, av in items:
            if op is _sre_c.LITERAL and ord(ch) == av:
                return True
            if op is _sre_c.RANGE and av[0] <= ord(ch) <= av[1]:
                return True
            if op is _sre_c.CATEGORY and re.match(
                    {_sre_c.CATEGORY_SPACE: r"\s", _sre_c.CATEGORY_NOT_SPACE: r"\S",
                     _sre_c.CATEGORY_DIGIT: r"\d", _sre_c.CATEGORY_NOT_DIGIT: r"\D",
                     _sre_c.CATEGORY_WORD: r"\w", _sre_c.CATEGORY_NOT_WORD: r"\W"}.get(av, r"(?!)"),
                    ch):
                return True
        return False
    for ch in "xa0 -_:/.,'\"=\n":
        if accepts(ch) != negate:
            return ch
    return "x"


def _witness(seq):
    """A representative text this parsed sequence reads (the first non-empty
    branch at each alternation), assertions taken as met. Not always the shortest."""
    out = []
    for op, av in seq:
        if op is _sre_c.LITERAL:
            out.append(chr(av))
        elif op is _sre_c.NOT_LITERAL:
            out.append("y" if av == ord("x") else "x")
        elif op is _sre_c.ANY:
            out.append("x")
        elif op is _sre_c.IN:
            out.append(_class_char(av))
        elif op in _REPEATS or op is getattr(_sre_c, "POSSESSIVE_REPEAT", None):
            out.append(_witness(av[2]) * av[0])
        elif op is _sre_c.SUBPATTERN:
            out.append(_witness(av[-1]))
        elif op is getattr(_sre_c, "ATOMIC_GROUP", None):
            out.append(_witness(av))
        elif op is _sre_c.BRANCH:
            texts = [_witness(alt) for alt in av[1]]
            out.append(next((t for t in texts if t), texts[0]))
    return "".join(out)


def _shape_leads(seq, lead=""):
    """The text before each shape (b) in a parsed sequence, at any depth."""
    seq = list(seq)
    for i, (op, av) in enumerate(seq):
        here = lead + _witness(seq[:i])
        if _unbounded_space(seq[i]) and (
                (i + 1 < len(seq) and _unbounded_space(seq[i + 1]))
                or (i + 2 < len(seq) and _optional(seq[i + 1]) and _unbounded_space(seq[i + 2]))):
            yield here
        if op is _sre_c.SUBPATTERN:
            yield from _shape_leads(av[-1], here)
        elif op is _sre_c.BRANCH:
            for alt in av[1]:
                yield from _shape_leads(alt, here)
        elif op in _REPEATS or op is getattr(_sre_c, "POSSESSIVE_REPEAT", None):
            yield from _shape_leads(av[2], here)
        elif op is getattr(_sre_c, "ATOMIC_GROUP", None):
            yield from _shape_leads(av, here)
        elif op is _sre_c.ASSERT and av[0] == 1:
            yield from _shape_leads(av[1], here)


def _shape_seeds(rx, guards, mode):
    """Seeds that end right before a shape (b) in what the engine runs: the
    regex, and for a guarded entry each guard too."""
    sources = [rx.pattern]
    if mode == "guarded":
        sources += [g.pattern for g in guards]
    elif mode == "leadin":
        sources += [guards.pattern]
    seeds = []
    for source in sources:
        try:
            parsed = _sre_parse.parse(source, re.IGNORECASE)
        except re.error:
            continue
        for lead in _shape_leads(parsed):
            if lead not in seeds:
                seeds.append(lead)
    return seeds[:8]


def _shape_texts(seeds, n=PROBE_LEN):
    texts = {}
    for seed in seeds:
        texts[f"shape lead {seed!r}+newline run"] = seed + "\n" * n
        texts[f"shape lead {seed!r}+space run"] = seed + " " * n
    return texts


def _timed_params():
    for pattern, compiled in ENGINE._regex_patterns:
        for index, (mode, rx, guards) in enumerate(compiled):
            key = (pattern["id"], index)
            marks = ()
            if key in KNOWN_SLOW:
                # Not strict: whether the wall clock goes over CAP_S depends on the runner. The
                # ratchet for a quadratic entry is test_each_known_slow_entry_still_grows below.
                marks = pytest.mark.xfail(strict=False, reason=f"known slow: {KNOWN_SLOW[key]}")
            elif key in KNOWN_SLOW_HEAVY:
                marks = pytest.mark.xfail(strict=False, reason=f"known slow: {KNOWN_SLOW_HEAVY[key]}")
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
    texts = _probe_texts(seeds)
    texts.update(_shape_texts(_shape_seeds(rx, guards, mode)))
    for shape, text in texts.items():
        seconds, over = _best_timed(lambda: ENGINE._eval_regex(mode, rx, guards, text), CAP_S)
        if over or seconds > CAP_S:
            slow.append(f"on {shape}: {'over' if over else ''} {seconds:.2f} s")
    assert not slow, (f"{rule_id} #{index} ({mode}) exceeded {CAP_S} s at "
                      f"{PROBE_LEN} characters:\n" + "\n".join(slow))


def _growth_texts(rx, guards, mode, n):
    seeds = _seeds(ENGINE._regex_requirement.get(id(rx), ()))
    texts = _probe_texts(seeds, n)
    texts.update(_shape_texts(_shape_seeds(rx, guards, mode), n))
    return texts


def _family_grows(run, sizes=None):
    """True when `run(n)` (seconds, over_budget) grows faster than linear. Doubles n from
    GROW_START. Returns (grows, steps) where steps lists (n, seconds, ratio_to_previous)."""
    steps, prev = [], None
    n = GROW_START
    while n <= PROBE_LEN:
        seconds, over = run(n)
        if over:
            # Over the budget right after a step that could be measured: the budget is at least
            # GROW_RATIO times the stop time, so this step grew by more than the ratio.
            if prev and prev[1] >= GROW_MIN_S:
                steps.append((n, seconds, None))
                return True, steps
            break
        ratio = (seconds / prev[1]) if prev and prev[1] >= GROW_MIN_S else None
        steps.append((n, seconds, ratio))
        if ratio is not None and ratio >= GROW_RATIO:
            return True, steps
        if seconds > GROW_STOP_S:
            break
        prev = (n, seconds)
        n *= 2
    return False, steps


def _entry_grows(rule_id, index, mode, rx, guards):
    """True when some probe of the entry grows faster than linear with its size. Each step is
    the best of three runs."""
    first = _growth_texts(rx, guards, mode, GROW_START)
    for name in first:
        def run(n, name=name):
            text = _growth_texts(rx, guards, mode, n)[name]
            fn = lambda: ENGINE._eval_regex(mode, rx, guards, text)
            return _min_timed(fn, GROW_CAP_S)
        grows, _steps = _family_grows(run)
        if grows:
            return True
    return False


def _slow_entry_params():
    for pattern, compiled in ENGINE._regex_patterns:
        for index, (mode, rx, guards) in enumerate(compiled):
            if (pattern["id"], index) in KNOWN_SLOW:
                yield pytest.param(pattern["id"], index, mode, rx, guards,
                                   id=f"{pattern['id']}-{index}-{mode}")


@pytest.mark.slow
@pytest.mark.parametrize("rule_id,index,mode,rx,guards", list(_slow_entry_params()))
def test_each_known_slow_entry_still_grows(rule_id, index, mode, rx, guards):
    # The ratchet for KNOWN_SLOW. It compares run times at two sizes, so a fast or a slow
    # runner gives the same answer. Fixing an entry without removing it from the list fails here.
    if not hasattr(signal, "SIGALRM"):
        pytest.skip("the per-probe budget needs SIGALRM")
    if threading.current_thread() is not threading.main_thread():
        pytest.skip("the per-probe budget needs the main thread")
    assert _entry_grows(rule_id, index, mode, rx, guards), (
        f"{rule_id} #{index} no longer grows faster than its input; remove it from KNOWN_SLOW")


@pytest.mark.parametrize("speed", [0.1, 1, 10], ids=["ten_times_faster", "as_measured", "ten_times_slower"])
def test_the_growth_check_tells_linear_from_quadratic(speed):
    # Synthetic work, no engine: a linear and a quadratic loop, sized so the smaller run is
    # long enough to measure. The measured seconds are scaled by `speed`, so the same two
    # loops stand for a runner ten times faster and ten times slower. A run past GROW_CAP_S
    # is reported as over, as the real probe reports it. Runs at once, needs no SIGALRM.
    def timed(work):
        def run(n):
            best = None
            for _ in range(3):
                t0 = time.perf_counter()
                work(n)
                spent = (time.perf_counter() - t0) * speed
                best = spent if best is None else min(best, spent)
            return best, best > GROW_CAP_S
        return run

    def linear(n):
        sum(range(n * 400))

    def quadratic(n):
        sum(i * j for i in range(n // 4) for j in range(n // 4))

    assert _family_grows(timed(quadratic))[0]
    assert not _family_grows(timed(linear))[0]


def test_one_slow_run_among_fast_ones_is_not_over_the_cap():
    if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        pytest.skip("the per-probe budget needs SIGALRM on the main thread")
    calls = []

    def sometimes_slow():
        calls.append(1)
        if len(calls) == 1:
            time.sleep(0.4)

    seconds, over = _best_timed(sometimes_slow, 0.1)
    assert not over and seconds <= 0.1
    assert len(calls) == 2


def test_a_run_that_is_over_the_cap_every_time_is_still_over():
    if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        pytest.skip("the per-probe budget needs SIGALRM on the main thread")
    calls = []

    def always_slow():
        calls.append(1)
        time.sleep(0.4)

    _seconds, over = _best_timed(always_slow, 0.1)
    assert over
    assert len(calls) == 3
