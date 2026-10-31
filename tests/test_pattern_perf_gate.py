"""scripts/pattern_perf_gate.py: the dynamic tripwire for a pattern change whose regex takes longer on large inputs.

The shape lint is static. This gate times the regexes a pull request changes, base against head,
and fails on superlinear growth, on a large head/base jump, on a run that hits the cap, on a waiver
that does not trip, on work the wall budget left undone and on a table it cannot read. The tests drive it with synthetic rule tables and, for the end-to-end
cases, a regex that is quadratic on purpose next to one that is linear; the end-to-end cases use small
synthetic inputs.
"""
import ast
import contextlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import time
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "pattern_perf_gate.py"
spec = importlib.util.spec_from_file_location("pattern_perf_gate", SCRIPT)
g = importlib.util.module_from_spec(spec)
sys.modules["pattern_perf_gate"] = g
spec.loader.exec_module(g)

SMALL = (1000, 2000, 4000)
SMALL_ADDED = (1000, 2000)
QUADRATIC = r"a+b"               # no `b` in the text: every start walks to the end of the run
LINEAR = r"read\s+token"


_NONE = object()


def run(base, head, waivers_base=_NONE, waivers_head=None, **kw):
    kw.setdefault("sizes", SMALL)
    kw.setdefault("added_sizes", SMALL_ADDED)
    kw.setdefault("repeats", 1)
    kw.setdefault("growth_floor", 0)
    kw.setdefault("ratio_floor", 0)
    return g.gate(base, head, {} if waivers_base is _NONE else waivers_base, waivers_head or {}, **kw)


# The text a quadratic expression is slow on: a run of `a` with no `b` or `c` after it. Any other text costs it only
# a little, so a gate that times an expression on the units picked for another one sees no growth and fails the test.
OWN_WORKLOAD = {QUADRATIC: "aaaa", r"a+c": "aaaa"}
OTHER_UNITS_S = 1e-12


def _by_shape(monkeypatch, shapes):
    """time_once that answers from the regex's pattern and the text it is given: seconds = k * len(text) ** power when
    the text is that pattern's own workload (OWN_WORKLOAD; any text where none is named), a small cost per character
    otherwise."""
    def fake(rxs, text, cap=g.RUN_CAP_S):
        seconds = 0.0
        for rx in rxs:
            k, power = shapes[rx.pattern]
            seconds += k * len(text) ** power if text.startswith(OWN_WORKLOAD.get(rx.pattern, "")) else OTHER_UNITS_S * len(text)
        return seconds
    monkeypatch.setattr(g, "time_once", fake)


# fixed seconds for the end-to-end cases: the quadratic pattern grows with the square of the text, the linear ones with its length
SHAPES = {QUADRATIC: (1e-8, 2), LINEAR: (1e-9, 1), r"read\s+tokens?": (1e-9, 1)}


# What the guard compares with and watches, taken when this file is loaded: a test that patches the module
# afterwards moves neither the floors nor the functions.
PRODUCTION_FLOORS = (g.GROWTH_FLOOR_S, g.RATIO_FLOOR_S)
REAL_TIME_ONCE = g.time_once
REAL_JUDGE = g.judge
GATE_BY_ANOTHER_NAME = g.gate
TIMER_BY_ANOTHER_NAME = g.time_once
GROWTH_FLOOR_NAME = "growth" + "_floor"
RATIO_FLOOR_NAME = "ratio" + "_floor"
# Where `judge` takes its two floors, by position in its local names: a copy with other local names still takes them there.
JUDGE_FLOORS_AT = tuple(REAL_JUDGE.__code__.co_varnames.index(n) for n in (GROWTH_FLOOR_NAME, RATIO_FLOOR_NAME))


def _below(floors):
    return floors[0] < PRODUCTION_FLOORS[0] or floors[1] < PRODUCTION_FLOORS[1]


def _signature(code):
    """What makes two code objects the same function: bytecode, global names and constants, not the name, the file or the local names."""
    return code.co_code, code.co_names, code.co_consts


REAL_CODE = {"timer": _signature(REAL_TIME_ONCE.__code__), "judge": _signature(REAL_JUDGE.__code__)}


class ClockWatch:
    """Watches the code of `time_once` and `judge` run, under whatever name or code object carries it.

    Matching is by signature (bytecode, global names and constants; not the name, the file or the local variable
    names) of the two functions as they were when this file loaded, so an alias, a wrapper, a copy of the function,
    `__code__.replace(...)` and the script executed again into a new module are all seen. A violation is the real
    `time_once` running while the nearest caller that holds both floors holds a floor under the production one
    ("measured"), or `judge` being given such floors after the real `time_once` ran in the same test, in any of its
    fixtures or in the test itself ("judged"). A replacement of `time_once` (fixed samples) never runs the real
    code, so it is not a violation by itself; a test that also ran the real one earlier is judged as mixed real and
    fixed work and its `judge` call is recorded.

    The watch can only see through the profile functions it installed. Taking one out during a test by calling
    `sys.setprofile` or `threading.setprofile` by name, even to put it back, is a violation ("replaced"); an
    interpreter that drops it (at the recursion limit) shows in `alive`. Events go on to the profile function that
    was in place: the test thread's own, and for a worker the one set for threads. Covered: the test's own thread
    and threads started while the watch is installed (a worker that outlives its install puts back, at its next event, the
    profile function it had when that install began). Not covered: a child process; a measurement made before this
    module's fixture is set up or after it is torn down; a profile function put in and taken out through a reference
    to either setter taken before this module's fixture ran, through the C interface, or by writing the thread
    module's stored function (`threading._profile_hook`) directly; a function whose bytecode,
    global names or constants differ from the two (a patched copy); and a `time_once` call with no caller that holds
    both floors, which has no floors to compare. The xunit hooks and a floor named in a code string are refused
    statically, and so is any use of the low-level thread interface (`_thread`, which a thread profile
    function does not reach). A call of `judge` whose floors cannot be read is a violation ("unreadable") and does not
    switch the watch off."""

    def __init__(self):
        self.violations = []          # (test id, floors or None, "measured", "judged", "replaced" or "unreadable")
        self.checked = 0              # how many of them a test or module teardown has already reported
        self.real_in = set()          # ids of the tests in which the real time_once ran (setup, call and teardown count as one test)
        self.muted = False
        self._hook = None             # the profile function of the current install: each install makes its own
        self._previous = None
        self._thread_previous = None
        self._owner = None
        self._kinds = {}              # id of a code object -> (the code object, "timer", "judge" or None)

    def install(self):
        self._previous = sys.getprofile()
        self._thread_previous = getattr(threading, "getprofile", lambda: threading._profile_hook)()   # getprofile: 3.10 and later
        self._owner = threading.get_ident()
        self._set_profile = sys.setprofile
        self._set_thread_profile = threading.setprofile
        self._hook, self._live = self._make_hook()
        self._set_profile(self._hook)
        self._set_thread_profile(self._hook)
        sys.setprofile = self._refuse_a_replacement
        threading.setprofile = self._refuse_a_thread_replacement

    def uninstall(self):
        self._live.live = False
        sys.setprofile = self._set_profile
        threading.setprofile = self._set_thread_profile
        self._set_profile(self._previous)
        self._set_thread_profile(self._thread_previous)

    def _refuse_a_replacement(self, function):
        if function != self._hook and not self.muted and self._watching_this_thread():   # a new thread putting the hook in is not a replacement
            self._record(None, "replaced")
        self._set_profile(function)

    def _refuse_a_thread_replacement(self, function):
        if function != self._hook and not self.muted and self._watching_this_thread():
            self._record(None, "replaced")
        self._set_thread_profile(function)

    def _watching_this_thread(self):
        """The test thread, or a worker that still has this install's hook. A worker left over from an earlier install
        has already put its own profile function back (the call that brought it here fired its hook first) and is no
        longer the watch's business."""
        return threading.get_ident() == self._owner or sys.getprofile() == self._hook

    def alive(self):
        return sys.getprofile() == self._hook

    def reinstall(self):
        """Puts the hook back where something switched it off. CPython drops a profile function that cannot run,
        as at the recursion limit."""
        if not self.alive():
            self._set_profile(self._hook)

    @contextlib.contextmanager
    def silenced(self):
        self.muted = True
        try:
            yield
        finally:
            self.muted = False

    @staticmethod
    def _floors_in_force(frame):
        while frame is not None:
            held = frame.f_locals
            if GROWTH_FLOOR_NAME in held and RATIO_FLOOR_NAME in held:          # bound now, not only named
                return held[GROWTH_FLOOR_NAME], held[RATIO_FLOOR_NAME]
            frame = frame.f_back
        return None

    @staticmethod
    def _judge_floors(frame):
        """The floors `judge` was called with, read by position; None where they cannot be read."""
        names, held = frame.f_code.co_varnames, frame.f_locals
        try:
            return tuple(held[names[i]] for i in JUDGE_FLOORS_AT)
        except (IndexError, KeyError):
            return None

    @staticmethod
    def _test():
        return os.environ.get("PYTEST_CURRENT_TEST", "").rsplit(" (", 1)[0]

    def _record(self, floors, how):
        self.violations.append((os.environ.get("PYTEST_CURRENT_TEST", ""), floors, how))

    def _kind(self, code):
        known = self._kinds.get(id(code))
        if known is None:
            signature = _signature(code)
            kind = next((name for name, real in REAL_CODE.items() if signature == real), None)
            known = self._kinds[id(code)] = (code, kind)               # the code object is kept, so its id stays its own
        return known[1]

    def _make_hook(self):
        """The profile function of one install. It holds what that install found, so a worker that outlives the install
        puts back exactly that at its next event, and a thread of a later install never meets it."""
        previous, thread_previous, owner = self._previous, self._thread_previous, self._owner
        state = types.SimpleNamespace(live=True)

        def hook(frame, event, arg):
            if not state.live:
                if threading.get_ident() != owner:
                    self._set_profile(thread_previous)
                return
            if event == "call" and not self.muted:
                try:
                    self._look_at(frame)
                except Exception:                    # an exception out of a profile function switches the profiler off
                    self._record(None, "unreadable")
            earlier = previous if threading.get_ident() == owner else thread_previous
            if earlier is not None:
                earlier(frame, event, arg)
        return hook, state

    def _look_at(self, frame):
        kind = self._kind(frame.f_code)
        if kind == "timer":
            self.real_in.add(self._test())
            floors = self._floors_in_force(frame.f_back)
            if floors is not None and _below(floors):
                self._record(floors, "measured")
        elif kind == "judge" and self._test() in self.real_in:
            floors = self._judge_floors(frame)
            if floors is None:
                self._record(None, "unreadable")
            elif _below(floors):
                self._record(floors, "judged")


WATCH = ClockWatch()


def _message(records):
    replaced = [r for r in records if r[2] == "replaced"]
    unreadable = [r for r in records if r[2] == "unreadable"]
    timed = [r for r in records if r[2] not in ("replaced", "unreadable")]
    parts = []
    if timed:
        floors = sorted({r[1] for r in timed}, key=str)
        tests = sorted({r[0] for r in timed})[:3]
        parts.append(f"{len(timed)} real-clock measurement(s) or verdict(s) with floors {floors}, below the production floors "
                     f"{PRODUCTION_FLOORS}, in {tests}: give the test fixed samples (_by_shape) or floors at or above them")
    if replaced:
        parts.append(f"{len(replaced)} replacement(s) of the profile function through sys.setprofile in "
                     f"{sorted({r[0] for r in replaced})[:3]}: a measurement made while it was away could not be seen, "
                     "so no test here may replace it")
    if unreadable:
        parts.append(f"{len(unreadable)} call(s) in {sorted({r[0] for r in unreadable})[:3]} whose floors the watch could "
                     "not read: the verdict function was called in a shape it does not know")
    return "; ".join(parts)


@pytest.fixture(autouse=True, scope="module")
def _watch_the_clock_for_the_module():
    WATCH.install()
    yield WATCH
    WATCH.uninstall()
    late = WATCH.violations[WATCH.checked:]          # made after the last test's own check: in another fixture's teardown
    WATCH.checked = len(WATCH.violations)
    assert not late, _message(late)


@pytest.fixture(autouse=True)
def _no_measurement_below_the_production_floors(_watch_the_clock_for_the_module):
    WATCH.reinstall()
    yield
    pending = WATCH.violations[WATCH.checked:]        # includes what an earlier test's other fixture made after this one ran
    WATCH.checked = len(WATCH.violations)
    assert not pending, _message(pending)
    assert WATCH.alive(), (
        "the clock watch was switched off during this test, so a measurement in it could not be seen: "
        "keep the test off the recursion limit or put the watch back as soon as it is over")


# ---------------------------------------------------------------- changed ids

def test_changed_ids_splits_added_changed_removed_and_unchanged():
    base = {"A": ("x",), "B": ("y",), "C": ("z",)}
    head = {"A": ("x",), "B": ("y2",), "D": ("w",)}
    changed, added = g.changed_ids(base, head)
    assert changed == {"B"}
    assert added == {"D"}


def test_a_rule_with_no_regex_is_not_timed():
    changed, added = g.changed_ids({}, {"A": ()})
    assert not changed and not added


PAT = 'PATTERNS = [{"id": "P1", "regex": ["a", "b"]}, {"id": "P2"}]\n'
MECH = 'MECHANISM_PATTERNS = [{"id": "M1", "regex": ["c"]}]\n'


def test_rules_from_sources_reads_both_tables():
    out = g.rules_from_sources({"sunglasses/patterns.py": PAT, "sunglasses/mechanisms.py": MECH})
    assert out == {"P1": ("a", "b"), "P2": (), "M1": ("c",)}


def test_a_missing_table_file_fails_closed():
    with pytest.raises(g.GateError, match="not readable"):
        g.rules_from_sources({"sunglasses/patterns.py": PAT, "sunglasses/mechanisms.py": None})


def test_an_empty_table_fails_closed():
    with pytest.raises(g.GateError, match="empty"):
        g.rules_from_sources({"sunglasses/patterns.py": "PATTERNS = []\n", "sunglasses/mechanisms.py": MECH})


def test_a_duplicate_id_fails_closed_inside_a_table_and_across_tables():
    dup = 'PATTERNS = [{"id": "X", "regex": ["a"]}, {"id": "X", "regex": ["b"]}]\n'
    with pytest.raises(g.GateError, match="more than once"):
        g.rules_from_sources({"sunglasses/patterns.py": dup, "sunglasses/mechanisms.py": MECH})
    across = 'MECHANISM_PATTERNS = [{"id": "P1", "regex": ["c"]}]\n'
    with pytest.raises(g.GateError, match="more than once"):
        g.rules_from_sources({"sunglasses/patterns.py": PAT, "sunglasses/mechanisms.py": across})


def _src(prelude):
    return {"sunglasses/patterns.py": prelude + PAT, "sunglasses/mechanisms.py": MECH}


@pytest.mark.parametrize("prelude", [
    "import sys\nsys.exit(0)\n",                         # a clean exit before the table is read
    "import os\nos._exit(0)\n",                          # the hardest exit there is
    "raise SystemExit(0)\n",
    "exit(0)\n",
    "import sys\nif 'perf' in sys.argv[0] or 'result' in sys.argv[3]:\n    sys.exit(0)\n",   # a conditional exit
    # a source that writes the loader's own result file for the table it likes, then leaves
    "import json, sys\njson.dump({'ok': True, 'table': 'PATTERNS', 'rules': [['P1', ['a']]]}, open(sys.argv[3], 'w'))\nsys.exit(0)\n",
    "import json, sys\njson.dump({'ok': True}, open(sys.argv[3], 'w'))\nsys.exit(7)\n",
    # a source that replaces the serializer the loader would use
    "import json\njson.dump = lambda *a, **k: None\n",
    "__import__('os')._exit(0)\n",
    "x = ().__class__.__bases__\n",                       # a way out through an object's own attributes
    "x = open('/nonexistent')\n",                          # an I/O call
    "import time\ntime.sleep(30)\n",
    "while True:\n    pass\n",
    "f = lambda: 1\n",
    "class C:\n    pass\n",
    "@staticmethod\ndef f():\n    return 1\n",
    "import_me = [].append(1)\n",                          # a method that is not on the list
    "def f():\n    raise SystemExit(0)\n",
    "def f():\n    for x in y:\n        pass\n",
    "x = __builtins__\n",                                  # the interpreter's own namespace
    "x = []\nx[0] = 1\n",                                 # an assignment to something that is not a name
    "str(1)\n",                                            # a statement that is a call, not a docstring
    "import os\n",                                         # an import, even one nothing uses
])
def test_a_table_source_that_runs_anything_but_plain_assignments_is_refused_not_run(prelude, tmp_path):
    marker = tmp_path / "ran"
    src = _src(prelude.replace("/nonexistent", str(marker)))
    with pytest.raises(g.GateError, match="plain constructs"):
        g.rules_from_sources(src)
    assert not marker.exists()


def test_a_source_that_does_not_parse_or_names_no_table_is_a_failure():
    with pytest.raises(g.GateError, match="does not parse"):
        g.rules_from_sources(_src("this is not python (\n"))
    with pytest.raises(g.GateError, match="no PATTERNS list"):
        g.rules_from_sources({"sunglasses/patterns.py": "X = 1\n", "sunglasses/mechanisms.py": MECH})
    with pytest.raises(g.GateError, match="string id"):
        g.rules_from_sources({"sunglasses/patterns.py": 'PATTERNS = [{"id": 1, "regex": ["a"]}]\n',
                              "sunglasses/mechanisms.py": MECH})
    with pytest.raises(g.GateError, match="string id"):
        g.rules_from_sources({"sunglasses/patterns.py": 'PATTERNS = [{"id": "A", "regex": [1]}]\n',
                              "sunglasses/mechanisms.py": MECH})


def _no_measurement_while_the_watch_is_off(*args, **kw):
    raise AssertionError("a gate function was called while the clock watch could be off")


def test_a_source_that_fails_while_being_evaluated_is_a_failure(monkeypatch):
    # the second source runs to the recursion limit, where the interpreter drops the profile function: no gate
    # function may run until the watch is put back, which the test does as soon as the sources have been read
    for name in ("time_once", "median_time", "judge", "gate", "main"):
        monkeypatch.setattr(g, name, _no_measurement_while_the_watch_is_off)
    try:
        for prelude in ("x = undefined_name\n", "def f():\n    return f()\ny = f()\n", "x = 1 + 'a'\n"):
            with pytest.raises(g.GateError, match="could not be read"):
                g.rules_from_sources(_src(prelude))
    finally:
        WATCH.reinstall()


def test_the_constructs_the_real_tables_use_are_read():
    src = _src(
        "_A = 'x'\n_B = f'(?:{_A})y'\n"
        "def _j(*s: str) -> str:\n    \"\"\"doc\"\"\"\n    return '|'.join(f'{t}s?' for t in s)\n"
        "_C = _j('a', 'b') + r'|c'\n")
    src["sunglasses/patterns.py"] = src["sunglasses/patterns.py"].replace('["a", "b"]', '[_B, _C]')
    out = g.rules_from_sources(src)
    assert out["P1"] == ("(?:x)y", "as?|bs?|c")


def test_a_slow_evaluation_is_cut_off_by_the_time_left():
    big = "[" + ", ".join(["'q'"] * 300) + "]"
    slow = f"_L = {big}\n_N = len([1 for a in _L for b in _L for c in _L for d in _L if a == b and c == d and a == 'z'])\n"
    with pytest.raises(g.GateError, match="did not finish in the time left"):
        g.rules_from_sources(_src(slow), g.Budget(1.0))


def test_the_budget_runs_through_reading_and_a_spent_budget_fails_before_a_table_is_read():
    spent = g.Budget(10, clock=lambda: 100.0, started=0.0)
    with pytest.raises(g.GateError, match="wall budget was spent"):
        g.rules_from_sources(_src(""), spent)
    # and reading hands the table no more than the time that is left
    seen = []
    real = g._within
    g._within = lambda seconds, what, fn: (seen.append(seconds), real(seconds, what, fn))[1]
    try:
        g.rules_from_sources(_src(""), g.Budget(5.0))
    finally:
        g._within = real
    assert seen and all(0 < x <= 5.0 for x in seen)


def test_the_real_tables_load_standalone():
    sources = {p: (ROOT / p).read_text(encoding="utf-8") for p, _ in g.TABLES}
    rules = g.rules_from_sources(sources)
    assert len(rules) > 1000 and any(i.startswith("GLS-EX-") for i in rules)


# ---------------------------------------------------------------- verdict logic

def _t(a, b, c):
    return dict(zip(g.SIZES, (a, b, c)))


def test_linear_growth_passes():
    growth, ratio, why = g.judge(_t(.1, .2, .4), _t(.1, .2, .4), g.SIZES)
    assert why == [] and round(growth, 2) == 2.0 and round(ratio, 2) == 1.0


def test_superlinear_growth_fails():
    _, _, why = g.judge(None, _t(.1, .2, .9), g.SIZES)
    assert why and "growth" in why[0]


def test_growth_under_the_floor_never_flaps():
    _, _, why = g.judge(None, _t(.001, .002, .009), g.SIZES)
    assert why == []


def test_a_large_head_over_base_jump_fails_only_above_the_floor():
    assert g.judge(_t(.1, .2, .4), _t(.2, .4, .8), g.SIZES)[2][0].startswith("head/base")
    assert g.judge(_t(.01, .02, .04), _t(.02, .04, .08), g.SIZES)[2] == []


def test_a_head_run_that_hit_the_cap_fails():
    assert "cap" in g.judge(None, _t(.1, .2, None), g.SIZES)[2][0]


def test_a_base_run_that_hit_the_cap_and_a_head_that_finished_is_not_a_jump():
    growth, ratio, reasons = g.judge(_t(.1, .2, None), _t(.1, .15, .3), g.SIZES)
    assert ratio is None and reasons == []


def test_a_base_run_that_hit_the_cap_does_not_excuse_a_superlinear_head():
    reasons = g.judge(_t(.1, .2, None), _t(.1, .2, .9), g.SIZES)[2]
    assert reasons == ["superlinear growth"]


# ---------------------------------------------------------------- waivers

def test_a_waiver_needs_a_dated_reason_and_a_real_id():
    probs = g.check_waivers({"A": "2026-10-24 bounded by the engine window", "B": "no date", "Z": "2026-10-24 x"},
                            {"A": ("a",), "B": ("b",)})
    assert len(probs) == 2
    assert any("B" in p and "dated" in p for p in probs) and any("Z" in p and "not in the rules" in p for p in probs)


# ---------------------------------------------------------------- end to end, small sizes

def test_a_quadratic_head_regex_fails(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert failures and any(r["verdict"] == "FAIL" for r in rows)
    assert any("growth" in f or "head/base" in f for f in failures)


def test_a_linear_head_regex_passes():
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (r"read\s+tokens?",)}, growth_floor=1, ratio_floor=1)
    assert failures == [] and rows and all(r["verdict"] == "ok" for r in rows)


def test_an_unchanged_table_times_nothing():
    rows, failures, notes = run({"R": (QUADRATIC,)}, {"R": (QUADRATIC,)})
    assert rows == [] and failures == [] and "timing 0 + 0 new" in notes[0]


def test_a_new_quadratic_id_is_caught_by_growth_alone(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    rows, failures, _ = run({}, {"N": (QUADRATIC,)})
    assert failures and rows[0]["base"] is None and rows[0]["sizes"] == SMALL_ADDED


def test_a_waived_quadratic_prints_and_passes(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    waiver = {"R": "2026-10-24 the engine bounds this window"}
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, waivers_base=waiver, waivers_head=waiver)
    assert failures == [] and any(r["verdict"] == "WAIVED" for r in rows)


def test_a_stale_waiver_fails():
    _, failures, _ = run({"R": (LINEAR,)}, {"R": (r"read\s+tokens?",)},
                         waivers_base={"R": "2026-10-24 old"}, waivers_head={"R": "2026-10-24 old"},
                         growth_floor=1, ratio_floor=1)
    assert any("does not trip" in f for f in failures)


def test_a_waiver_removed_in_the_pull_request_changes_no_verdict_of_that_pull_request():
    rows, failures, notes = run({"R": (QUADRATIC,)}, {"R": (QUADRATIC,)},
                                waivers_base={"R": "2026-10-24 old"}, waivers_head={})
    assert rows == [] and failures == [] and "timing 0 + 0 new" in notes[0]


def test_the_wall_cap_fails_closed_and_names_what_was_not_run():
    clock = iter(range(0, 10_000, 100))
    rows, failures, _ = run({"A": (LINEAR,), "B": (LINEAR,)}, {"A": (QUADRATIC,), "B": (QUADRATIC,)},
                            wall_cap=150, clock=lambda: next(clock))
    assert any(r["verdict"] == "NOT-RUN" for r in rows)
    assert any("wall cap" in f for f in failures)


def test_the_run_cap_counts_as_a_failure(monkeypatch):
    monkeypatch.setattr(g, "time_once", lambda rxs, text, cap=g.RUN_CAP_S: None)
    _, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert failures and any("cap" in f for f in failures)


# ---------------------------------------------------------------- the timer is given back

@pytest.mark.skipif(not hasattr(__import__("signal"), "setitimer"), reason="no interval timer here")
def test_timing_leaves_the_alarm_signal_as_it_found_it():
    import signal
    before = signal.getsignal(signal.SIGALRM)
    assert g.time_once([__import__("re").compile("a")], "aaa") is not None
    assert signal.getsignal(signal.SIGALRM) == before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, growth_floor=1, ratio_floor=1)   # a whole gate run, cut or not, does the same
    assert signal.getsignal(signal.SIGALRM) == before


@pytest.mark.skipif(not hasattr(__import__("signal"), "setitimer"), reason="no interval timer here")
def test_a_gate_run_does_not_make_the_firewall_budget_lane_unavailable():
    # The firewall gives its pattern scan a SIGALRM budget only while the handler is the default.
    # A gate run that left its own handler behind turned every later firewall check into an "ask".
    run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, growth_floor=1, ratio_floor=1)
    from sunglasses import firewall as fw
    finished, _ = fw._run_within_budget(lambda: 1, 5)
    assert finished is True


# ---------------------------------------------------------------- sampler

def test_the_sampler_cuts_short_of_the_whole_match_and_adds_the_generic_units():
    units = g.sampled_units([r"read.{0,100}\.env.{0,220}paste.{0,100}issue"])
    assert any(u.startswith("read") and "paste" not in u for u in units)
    assert all(u in units for u in g.GENERIC_UNITS)
    assert len(units) == len(set(units))


def test_the_sampler_is_deterministic_and_survives_a_bad_regex():
    assert g.sampled_units([r"a+b"]) == g.sampled_units([r"a+b"])
    assert g.sampled_units(["("]) == list(g.GENERIC_UNITS)


# ---------------------------------------------------------------- command line

def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True).stdout.strip()


def _repo(tmp_path, base_regex, head_regex, waivers=None, head_mech=MECH):
    repo = tmp_path / "r"
    (repo / "sunglasses").mkdir(parents=True)
    _git(tmp_path, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    table = lambda rx: f'PATTERNS = [{{"id": "R1", "regex": [{rx!r}]}}]\n'
    (repo / "sunglasses" / "patterns.py").write_text(table(base_regex))
    (repo / "sunglasses" / "mechanisms.py").write_text(MECH)
    _git(repo, "add", "sunglasses/patterns.py", "sunglasses/mechanisms.py")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "sunglasses" / "patterns.py").write_text(table(head_regex))
    (repo / "sunglasses" / "mechanisms.py").write_text(head_mech)
    add = ["sunglasses/patterns.py", "sunglasses/mechanisms.py"]
    if waivers is not None:
        (repo / "tests").mkdir()
        (repo / "tests" / "pattern_perf_waivers.json").write_text(json.dumps(waivers))
        add.append("tests/pattern_perf_waivers.json")
    _git(repo, "add", *add)
    _git(repo, "commit", "-q", "--allow-empty", "-m", "head")
    return repo, base, _git(repo, "rev-parse", "HEAD")


def _env(**extra):
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
    env.update(extra)
    return env


def _cli(repo, *args, **env):
    return subprocess.run([sys.executable, str(SCRIPT), "--repo", str(repo), *args], capture_output=True,
                          text=True, env=_env(**env))


def test_cli_without_a_pull_request_exits_zero():
    r = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0 and "not a pull request" in r.stdout


def test_cli_rejects_a_ref_that_is_not_a_full_sha(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    r = _cli(repo, "--base", "main", "--head", head)
    assert r.returncode == 2


def test_cli_passes_when_nothing_changed(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 0 and "pattern-perf: pass" in r.stdout


def test_cli_writes_the_step_summary(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    out = tmp_path / "summary.md"
    r = _cli(repo, "--base", base, "--head", head, GITHUB_STEP_SUMMARY=str(out))
    assert "## pattern-perf" in out.read_text() and r.returncode == 0


def test_cli_rejects_a_malformed_waiver_file(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, waivers=["R1"])
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1 and "JSON object" in r.stderr


def _committed_waivers():
    """The waiver file of this tree; none yet is an empty set of waivers."""
    path = ROOT / g.WAIVERS
    return g.read_waivers(path.read_text(encoding="utf-8")) if path.exists() else {}


def test_the_committed_waiver_file_is_valid_and_every_entry_is_dated():
    waivers = _committed_waivers()
    rules = g.rules_from_sources({p: (ROOT / p).read_text(encoding="utf-8") for p, _ in g.TABLES})
    assert g.check_waivers(waivers, rules) == []


# ---------------------------------------------------------------- r2: the workload, per regex

def test_a_new_id_is_timed_at_the_larger_size_pair():
    assert g.ADDED_SIZES == g.SIZES[-2:]


def test_every_regex_of_a_new_id_is_judged_on_its_own_units(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    rows, failures, _ = run({}, {"N": (LINEAR, QUADRATIC)})
    cases = {r["case"].split("/")[0] for r in rows}
    assert cases == {"r0", "r1"}
    assert failures and all(f.startswith("N r1/") for f in failures)


def test_a_slow_second_expression_is_not_diluted_by_a_heavier_linear_first_one(monkeypatch):
    heavy_linear = r"(?:read\s+token\s*){1,40}x"
    heavy_k, (quad_k, quad_power) = 4e-4, SHAPES[QUADRATIC]
    _by_shape(monkeypatch, {**SHAPES, heavy_linear: (heavy_k, 1)})
    # the first expression costs more than the second at every measured size, so the two summed hide the growth from the gate
    assert all(heavy_k * n > quad_k * n ** quad_power for n in SMALL)
    summed = [heavy_k * n + quad_k * n ** quad_power for n in SMALL]
    assert summed[-1] / summed[-2] <= g.GROWTH_MAX < quad_k * SMALL[-1] ** quad_power / (quad_k * SMALL[-2] ** quad_power)
    # a ratio floor above every head time keeps the ratio lane quiet, so only the growth of the second expression can fail it
    rows, failures, _ = run({"R": (LINEAR, LINEAR)}, {"R": (heavy_linear, QUADRATIC)}, ratio_floor=1e3)
    assert any(f.startswith("R r1/") and "superlinear growth" in f for f in failures)
    assert not any("head/base jump" in f for f in failures)


def test_only_the_regexes_that_changed_are_timed_for_a_changed_id(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    rows, failures, _ = run({"R": (LINEAR, LINEAR)}, {"R": (LINEAR, QUADRATIC)})
    assert {r["case"].split("/")[0] for r in rows} == {"r1"}


def test_reordering_the_same_regexes_times_nothing_and_is_not_a_failure():
    rows, failures, _ = run({"R": (LINEAR, QUADRATIC)}, {"R": (QUADRATIC, LINEAR)})
    assert rows == [] and failures == []


def test_a_row_names_a_case_not_the_input_and_the_table_hides_the_input_by_default(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    rows, _, _ = run({}, {"N": (QUADRATIC,)})
    assert all(r["case"].startswith("r0/u") for r in rows)
    assert all(r["unit"] not in g.table(rows) for r in rows if len(r["unit"]) > 2)


# ---------------------------------------------------------------- r2: waivers

def test_a_waiver_that_only_the_head_has_never_decides_a_verdict(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, waivers_base={},
                            waivers_head={"R": "2026-10-24 reviewed"})
    assert failures and all(r["verdict"] != "WAIVED" for r in rows)


def test_a_waiver_that_only_the_head_has_does_not_count_for_a_new_id_either(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    rows, failures, _ = run({}, {"N": (QUADRATIC,)}, waivers_head={"N": "2026-10-24 reviewed"})
    assert failures and all(r["verdict"] != "WAIVED" for r in rows)


def test_a_waiver_in_the_base_on_a_new_id_must_trip_too():
    waiver = {"N": "2026-10-24 reviewed"}
    _, failures, _ = run({}, {"N": (LINEAR,)}, waivers_base=waiver, waivers_head=waiver,
                         growth_floor=1, ratio_floor=1)
    assert any("does not trip" in f for f in failures)


def test_a_waiver_nobody_touched_is_not_retimed():
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (LINEAR,)}, waivers_base={"R": "2026-10-24 old"},
                            waivers_head={"R": "2026-10-24 old"})
    assert rows == [] and failures == []


def test_a_waiver_only_pull_request_times_nothing_and_still_has_its_format_checked():
    rows, failures, notes = run({"R": (LINEAR,)}, {"R": (LINEAR,)}, waivers_base=None,
                                waivers_head={"R": "2026-10-24 reviewed"})
    assert rows == [] and failures == [] and "timing 0 + 0 new" in notes[0]
    _, failures, _ = run({"R": (LINEAR,)}, {"R": (LINEAR,)}, waivers_base={}, waivers_head={"R": "no date"})
    assert any("dated reason" in f for f in failures)


def test_cli_a_waiver_only_pull_request_passes_without_retiming_and_a_later_one_is_judged_by_the_base(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, waivers={"R1": "2026-10-24 seed"})
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 0 and "timing 0 + 0 new" in r.stdout
    (repo / "tests" / "pattern_perf_waivers.json").write_text(json.dumps({"R1": "2026-10-24 seed", "R9": "no date"}))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "again")
    r2 = _cli(repo, "--base", head, "--head", _git(repo, "rev-parse", "HEAD"))
    assert r2.returncode == 1 and "dated reason" in r2.stdout


# ---------------------------------------------------------------- the run cap in the ranking pre-pass

def _cap_in_the_prepass(monkeypatch):
    """time_once that reaches the cap at the ranking size only: every measured size then finishes."""
    def fake(rxs, text, cap=g.RUN_CAP_S):
        return None if len(text) == g.PREPASS_SIZE else 0.001
    monkeypatch.setattr(g, "time_once", fake)


def test_a_head_run_that_reaches_the_cap_in_the_prepass_fails_though_every_measured_size_finishes(monkeypatch):
    _cap_in_the_prepass(monkeypatch)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, growth_floor=1, ratio_floor=1)
    assert any(f.startswith("R r0/pre:") and "run cap" in f for f in failures)
    assert any(r["case"] == "r0/pre" and r["verdict"] == "FAIL" for r in rows)
    assert any(r["case"].startswith("r0/u") and r["verdict"] == "ok" for r in rows)   # the later sizes did finish
    assert "cap" in g.table(rows)


def test_a_base_waiver_is_the_only_exception_to_a_prepass_cap(monkeypatch):
    _cap_in_the_prepass(monkeypatch)
    waiver = {"R": "2026-10-24 the engine bounds this window"}
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, waivers_base=waiver, waivers_head=waiver,
                            growth_floor=1, ratio_floor=1)
    assert failures == [] and any(r["case"] == "r0/pre" and r["verdict"] == "WAIVED" for r in rows)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, waivers_base={}, waivers_head=waiver,
                            growth_floor=1, ratio_floor=1)
    assert failures                                          # a waiver only the head has is no exception


def test_a_waived_id_whose_only_trip_is_the_prepass_cap_still_trips(monkeypatch):
    _cap_in_the_prepass(monkeypatch)
    waiver = {"R": "2026-10-24 reviewed"}
    _, failures, _ = run({"R": (LINEAR,)}, {"R": (r"read\s+tokens?",)}, waivers_base=waiver, waivers_head=waiver,
                         growth_floor=1, ratio_floor=1)
    assert not any("does not trip" in f for f in failures)


# ---------------------------------------------------------------- r2: the budget

class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _slow_timer(monkeypatch, clock, step):
    def fake(rxs, text, cap=g.RUN_CAP_S):
        clock.t += step
        return 0.001
    monkeypatch.setattr(g, "time_once", fake)


def test_work_that_finishes_past_the_wall_cap_fails_even_for_the_last_item(monkeypatch):
    clock = _Clock()
    _slow_timer(monkeypatch, clock, 60.0)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (r"read\s+tokens?",)}, wall_cap=150, clock=clock,
                            repeats=1)
    assert failures and any("wall cap" in f for f in failures)


def test_a_measurement_cut_short_by_the_budget_is_not_a_verdict(monkeypatch):
    clock = _Clock()
    _slow_timer(monkeypatch, clock, 60.0)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, wall_cap=150, clock=clock, repeats=1)
    assert all(r["verdict"] in ("NOT-RUN", "ok", "FAIL", "WAIVED") for r in rows)
    assert any(r["verdict"] == "NOT-RUN" for r in rows) and any("wall cap" in f for f in failures)


def test_the_pre_pass_stops_when_the_budget_is_spent():
    b = g.Budget(cap=10, clock=lambda: 100.0, started=0.0)
    assert b.over() and g.pick_units([QUADRATIC], 3, b) == []


def test_a_run_never_gets_more_than_the_time_left(monkeypatch):
    caps = []
    monkeypatch.setattr(g, "time_once", lambda rxs, text, cap=g.RUN_CAP_S: caps.append(cap) or 0.001)
    clock = _Clock()
    clock.t = 148.0
    g.median_time([], "x", 1, g.Budget(cap=150, clock=clock, started=0.0))
    assert caps and max(caps) <= 2.0 + 1e-9


def test_a_zero_wall_cap_runs_nothing_and_fails(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, QUADRATIC)
    r = _cli(repo, "--base", base, "--head", head, "--wall-cap", "0")
    assert r.returncode == 1 and "wall" in r.stdout + r.stderr


def test_a_budget_spent_in_the_pre_pass_is_not_run_not_silently_untimed(monkeypatch):
    clock = _Clock()
    _slow_timer(monkeypatch, clock, 40.0)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, wall_cap=100, clock=clock, repeats=1)
    assert failures and rows and all(r["verdict"] == "NOT-RUN" for r in rows)


def test_a_regex_with_no_units_to_judge_it_on_is_not_run_not_passed(monkeypatch):
    monkeypatch.setattr(g, "pick_units", lambda regexes, keep, budget=None, capped=None: [])
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert [r["verdict"] for r in rows] == ["NOT-RUN"] and any("not run" in f for f in failures)


def test_a_last_measurement_that_ends_past_the_budget_is_not_a_pass(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(g, "pick_units", lambda regexes, keep, budget=None, capped=None: ["read token "])

    def slow_once(rxs, text, repeats, budget=None):
        clock.t += 200.0
        return 0.001

    monkeypatch.setattr(g, "median_time", slow_once)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, wall_cap=150, clock=clock, growth_floor=1,
                            ratio_floor=1)
    assert [r["verdict"] for r in rows] == ["NOT-RUN"] and any("wall cap" in f for f in failures)


@pytest.mark.parametrize("cap", range(5, 400, 17))
def test_a_pass_never_comes_from_a_run_that_outlived_its_budget(monkeypatch, cap):
    clock = _Clock()

    def tick():
        clock.t += 1.0
        return clock.t

    def fake(rxs, text, cap_=g.RUN_CAP_S):
        clock.t += 3.0
        return 0.001

    monkeypatch.setattr(g, "time_once", fake)
    start = clock.t
    rows, failures, _ = run({"A": (LINEAR,), "B": (LINEAR,)}, {"A": (r"read\s+tokens?",), "B": (r"read\s+tokens",)},
                            wall_cap=cap, clock=tick, repeats=1, growth_floor=1, ratio_floor=1)
    if not failures:
        assert clock.t - start <= cap


# ---------------------------------------------------------------- r2: noise

def _seq(values):
    it = iter(values)
    calls = []
    def fake(rxs, text, cap=g.RUN_CAP_S):
        calls.append(1)
        return next(it, values[-1])
    return fake, calls


def test_a_short_run_is_repeated_until_the_sample_is_worth_trusting(monkeypatch):
    fake, calls = _seq([0.001])
    monkeypatch.setattr(g, "time_once", fake)
    assert g.median_time([], "x", 3) == pytest.approx(0.001)
    assert len(calls) == g.MAX_REPEATS


def test_a_medium_run_gets_enough_repeats_to_total_about_half_a_second(monkeypatch):
    fake, calls = _seq([0.1])
    monkeypatch.setattr(g, "time_once", fake)
    g.median_time([], "x", 3)
    assert len(calls) == 5


def test_one_slow_outlier_among_short_runs_does_not_move_the_median(monkeypatch):
    fake, _ = _seq([0.02, 0.021, 0.30, 0.022, 0.02, 0.02, 0.021])
    monkeypatch.setattr(g, "time_once", fake)
    assert g.median_time([], "x", 3) < 0.03


def test_a_long_first_run_is_confirmed_and_the_lower_stands(monkeypatch):
    fake, calls = _seq([0.9, 0.3])
    monkeypatch.setattr(g, "time_once", fake)
    assert g.median_time([], "x", 3) == pytest.approx(0.3)
    assert len(calls) == 2


def test_a_run_near_the_cap_stands_alone(monkeypatch):
    fake, calls = _seq([g.RUN_CAP_S * 0.6])
    monkeypatch.setattr(g, "time_once", fake)
    g.median_time([], "x", 3)
    assert len(calls) == 1


def test_a_cap_in_any_repeat_is_a_cap(monkeypatch):
    fake, _ = _seq([0.001, 0.001, None])
    monkeypatch.setattr(g, "time_once", fake)
    assert g.median_time([], "x", 3) is None


# ---------------------------------------------------------------- r2: the log carries no numbers

def test_in_a_job_the_table_goes_to_the_summary_and_the_log_carries_verdict_words_only(tmp_path, monkeypatch):
    summary = tmp_path / "s.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    _by_shape(monkeypatch, SHAPES)
    rows, failures, notes = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    log = g.report(rows, failures, notes)
    assert "| id | case |" in summary.read_text() and "|" not in log
    assert "FAIL: R r0/u" in log and "superlinear growth" in log
    assert not re.search(r"\d+\.\d+", log)
    assert "job summary" in log


def test_with_no_summary_file_the_log_carries_the_table(monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    _by_shape(monkeypatch, SHAPES)
    rows, failures, notes = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert "| id | case |" in g.report(rows, failures, notes)


# ---------------------------------------------------------------- r2: inputs that cannot be judged

def test_cli_fails_closed_when_the_base_commit_is_not_in_the_checkout(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    r = _cli(repo, "--base", "0" * 40, "--head", head)
    assert r.returncode == 1 and "not in the checkout" in r.stderr


def test_cli_fails_closed_when_the_head_commit_is_not_in_the_checkout(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    r = _cli(repo, "--base", base, "--head", "1" * 40)
    assert r.returncode == 1 and "not in the checkout" in r.stderr


def test_cli_fails_closed_when_the_second_table_is_missing_at_the_base(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    _git(repo, "rm", "-q", "sunglasses/mechanisms.py")
    _git(repo, "commit", "-qm", "drop")
    r = _cli(repo, "--base", base, "--head", _git(repo, "rev-parse", "HEAD"))
    assert r.returncode == 1 and "not readable" in r.stderr


def test_cli_fails_closed_on_an_empty_head_table(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, head_mech="MECHANISM_PATTERNS = []\n")
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1 and "empty" in r.stderr


def test_cli_fails_closed_on_a_head_table_that_exits_before_it_is_read(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, head_mech="import sys\nsys.exit(0)\n" + MECH)
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1 and "plain constructs" in r.stderr


def test_cli_fails_closed_on_a_head_table_that_forges_the_loaders_result_and_leaves(tmp_path):
    forged = ("import json, sys\njson.dump({'ok': True, 'table': 'MECHANISM_PATTERNS', 'rules': [['M1', ['c']]]}, "
              "open(sys.argv[3], 'w'))\nsys.exit(0)\n")
    repo, base, head = _repo(tmp_path, LINEAR, QUADRATIC, head_mech=forged + MECH)
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1 and "plain constructs" in r.stderr


def test_cli_cuts_a_table_that_takes_longer_to_read_than_the_time_left(tmp_path):
    big = "[" + ", ".join(["'q'"] * 400) + "]"
    slow = f"_L = {big}\n_N = len([1 for a in _L for b in _L for c in _L for d in _L if a == b and c == d and a == 'z'])\n"
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, head_mech=slow + MECH)
    start = time.monotonic()
    r = _cli(repo, "--base", base, "--head", head, "--wall-cap", "2")
    assert r.returncode == 1 and "did not finish in the time left" in r.stderr
    assert time.monotonic() - start < 20


def test_cli_fails_closed_on_a_duplicate_id_hidden_behind_an_unchanged_row(tmp_path):
    dup = 'MECHANISM_PATTERNS = [{"id": "M1", "regex": ["c"]}, {"id": "M1", "regex": ["d"]}]\n'
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, head_mech=dup)
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1 and "more than once" in r.stderr


# ---------------------------------------------------------------- r2: public prose

def test_the_waiver_reasons_carry_no_branch_name_workload_or_speed_claim():
    waivers = _committed_waivers()
    bad = {k: v for k, v in waivers.items()
           if re.search(r"\bmain\b|\d+\s*(?:k|kb|ms|s|seconds?)\b|\bunder a second\b|\bshape\b", v, re.I)}
    assert bad == {}


# ---------------------------------------------------------------- r3: deadline, confirmation, waivers

def test_a_budget_spent_while_the_tables_were_read_fails_even_if_each_read_finished(monkeypatch):
    clock = _Clock()

    def slow_read(source, path, table):
        clock.t += 100.0
        return [("A" + table, ("x",))]
    monkeypatch.setattr(g, "_read_table", slow_read)
    with pytest.raises(g.GateError, match="wall budget was spent"):
        g.rules_from_sources({"sunglasses/patterns.py": "", "sunglasses/mechanisms.py": ""},
                             g.Budget(150, clock=clock, started=0.0))


def test_an_empty_worklist_after_the_budget_is_spent_is_not_a_pass():
    rules = {"R": (LINEAR,)}
    rows, failures, _ = run(rules, rules, wall_cap=150, clock=lambda: 200.0, started=0.0)
    assert rows == [] and any("wall cap was reached before the run finished" in f for f in failures)


def test_an_empty_worklist_inside_the_budget_still_passes():
    rules = {"R": (LINEAR,)}
    rows, failures, _ = run(rules, rules, wall_cap=150, clock=lambda: 10.0, started=0.0)
    assert rows == [] and failures == []


def test_a_capped_confirmation_is_a_cap_not_the_earlier_sample(monkeypatch):
    fake, calls = _seq([0.9, None])
    monkeypatch.setattr(g, "time_once", fake)
    assert g.median_time([], "x", 3) is None
    assert len(calls) == 2


def test_a_capped_confirmation_fails_the_whole_gate(monkeypatch):
    monkeypatch.setattr(g, "pick_units", lambda regexes, keep, budget=None, capped=None: ["read token "])
    state = {"n": 0}

    def fake(rxs, text, cap=g.RUN_CAP_S):
        state["n"] += 1
        return 0.9 if state["n"] % 2 else None      # every long first sample is followed by a capped one
    monkeypatch.setattr(g, "time_once", fake)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (r"read\s+tokens?",)})
    assert failures and any("run cap" in f for f in failures)
    assert all(r["verdict"] != "ok" for r in rows)


def test_a_waived_id_whose_unchanged_expression_still_trips_is_not_stale_after_a_harmless_sibling_edit(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    waiver = {"R": "2026-10-24 the engine bounds this window"}
    rows, failures, _ = run({"R": (QUADRATIC, LINEAR)}, {"R": (QUADRATIC, r"read\s+tokens?")},
                            waivers_base=waiver, waivers_head=waiver)
    assert failures == []
    assert {r["case"][:2] for r in rows} == {"r0", "r1"}          # the whole id was timed, not the edit
    assert any(r["verdict"] == "WAIVED" for r in rows)


def test_a_waived_id_whose_every_expression_is_now_linear_is_still_stale():
    waiver = {"R": "2026-10-24 old"}
    _, failures, _ = run({"R": (QUADRATIC, LINEAR)}, {"R": (LINEAR, r"read\s+tokens?")},
                         waivers_base=waiver, waivers_head=waiver, growth_floor=1, ratio_floor=1)
    assert any("does not trip" in f for f in failures)


def test_a_changed_id_without_a_waiver_is_still_timed_on_the_changed_expression_only(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    rows, _, _ = run({"R": (QUADRATIC, LINEAR)}, {"R": (QUADRATIC, r"read\s+tokens?")})
    assert {r["case"][:2] for r in rows} == {"r1"}


@pytest.mark.parametrize("mode", ["pull_request", "all"])
def test_main_hands_one_budget_to_the_reader_and_the_gate(tmp_path, monkeypatch, mode):
    repo, base, head = _repo(tmp_path, LINEAR, QUADRATIC)
    seen = {"read": [], "gate": []}
    real_read = g.rules_from_sources
    monkeypatch.setattr(g, "rules_from_sources",
                        lambda src, budget=None: (seen["read"].append(budget), real_read(src, budget))[1])
    monkeypatch.setattr(g, "gate", lambda *a, **k: (seen["gate"].append(k.get("budget")), ([], [], []))[1])
    before = time.monotonic()
    args = ["--repo", str(repo), "--wall-cap", "100"]
    args += ["--all"] if mode == "all" else ["--base", base, "--head", head]
    assert g.main(args) == 0
    (gate_budget,) = seen["gate"]
    assert isinstance(gate_budget, g.Budget) and seen["read"] and all(b is gate_budget for b in seen["read"])
    assert before <= gate_budget.started <= time.monotonic() and gate_budget.cap == 100


# ---------------------------------------------------------------- r2: head against base

def _by_pattern(monkeypatch, per_char_ms):
    """time_once that answers from the regex's pattern: linear in the text, with the slope given."""
    def fake(rxs, text, cap=g.RUN_CAP_S):
        return sum(per_char_ms[rx.pattern] for rx in rxs) * len(text) / 1e6
    monkeypatch.setattr(g, "time_once", fake)


def test_a_linear_but_much_slower_head_regex_fails_on_the_ratio_alone(monkeypatch):
    _by_pattern(monkeypatch, {"aaa": 1.0, "bbb": 3.0})
    rows, failures, _ = run({"R": ("aaa",)}, {"R": ("bbb",)})
    assert failures and all("head/base jump" in f and "growth" not in f for f in failures)
    assert all(r["base"] is not None for r in rows)


def test_a_slightly_slower_linear_head_regex_passes(monkeypatch):
    _by_pattern(monkeypatch, {"aaa": 1.0, "bbb": 1.5})
    rows, failures, _ = run({"R": ("aaa",)}, {"R": ("bbb",)})
    assert failures == [] and rows


def test_a_changed_second_regex_is_compared_with_the_base_second_regex(monkeypatch):
    _by_pattern(monkeypatch, {"aaa": 1.0, "bbb": 3.0, "ccc": 1.0})
    rows, failures, _ = run({"R": ("aaa", "ccc")}, {"R": ("aaa", "bbb")})
    assert {r["case"].split("/")[0] for r in rows} == {"r1"}
    assert failures and all(f.startswith("R r1/") for f in failures)


# ---------------------------------------------------------------- the base decides: waivers and the head as data

def test_a_rule_change_and_a_waiver_file_change_together_fail():
    base, head = {"R": (LINEAR,)}, {"R": (QUADRATIC,)}
    problems = g.waiver_conflict(base, head, "{}", '{"R": "2026-10-24 reason"}')
    assert len(problems) == 1 and "pull request of its own" in problems[0]


def test_an_added_rule_or_a_removed_rule_counts_as_changing_a_rule():
    for base, head in (({}, {"R": (LINEAR,)}), ({"R": (LINEAR,)}, {})):
        assert g.waiver_conflict(base, head, None, '{"R": "2026-10-24 reason"}')


def test_a_rule_changed_to_an_empty_list_counts_as_changing_a_rule():
    assert g.waiver_conflict({"R": (LINEAR,)}, {"R": ()}, "{}", '{"R": "2026-10-24 reason"}')


def test_a_head_that_changes_no_rule_may_change_the_waiver_file():
    rules = {"R": (LINEAR,)}
    assert g.waiver_conflict(rules, dict(rules), "{}", '{"R": "2026-10-24 reason"}') == []


def test_an_edit_that_keeps_every_entry_adds_nothing_so_it_is_not_a_conflict():
    base, head = {"R": (LINEAR,)}, {"R": (QUADRATIC,)}
    assert g.waiver_conflict(base, head, '{"R": "2026-10-24 r"}', '{"R":   "2026-10-24 r"}') == []
    assert g.waiver_conflict(base, head, None, "{}") == []           # an empty file adds no entry


def test_an_unchanged_waiver_file_is_not_a_problem_when_a_rule_changes():
    base, head = {"R": (LINEAR,)}, {"R": (QUADRATIC,)}
    text = '{"R": "2026-10-24 r"}'
    assert g.waiver_conflict(base, head, text, text) == []
    assert g.waiver_conflict(base, head, None, None) == []           # no file on either side


def test_cli_a_rule_change_that_brings_its_own_waiver_fails_and_the_waiver_does_not_count(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, QUADRATIC, waivers={"R1": "2026-10-24 reason"})
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1
    assert "pull request of its own" in r.stdout
    assert "WAIVED" not in r.stdout                        # the quadratic head is judged with no waiver


def test_cli_the_head_is_data_a_source_that_does_something_is_refused_and_never_runs(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    mark = tmp_path / "ran"
    evil = ('PATTERNS = [{"id": "R1", "regex": [__import__("pathlib").Path(%r).write_text("x") and "a"]}]\n' % str(mark))
    (repo / "sunglasses" / "patterns.py").write_text(evil)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "evil")
    r = _cli(repo, "--base", base, "--head", _git(repo, "rev-parse", "HEAD"))
    assert r.returncode == 1 and not mark.exists()


def test_cli_reads_the_head_by_sha_not_from_the_working_tree(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    (repo / "sunglasses" / "patterns.py").write_text("this is not python (\n")      # dirty tree, ignored
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_sha_with_a_trailing_newline_is_not_a_sha(capsys):
    assert g.main(["--base", "a" * 40 + "\n", "--head", "b" * 40]) == 2
    assert g.main(["--base", "a" * 40, "--head", "b" * 40 + "\n"]) == 2
    assert "40-character" in capsys.readouterr().err


# ---------------------------------------------------------------- C249: merge-base tables, removal-only waiver edits

W1 = "2026-10-24 reason one"
W2 = "2026-10-24 reason two"


def test_a_rule_change_may_remove_waivers():
    base, head = {"R": (QUADRATIC,)}, {"R": (LINEAR,)}
    both = json.dumps({"R": W1, "S": W2})
    assert g.waiver_conflict(base, head, both, json.dumps({"S": W2})) == []     # one entry removed
    assert g.waiver_conflict(base, head, both, "{}") == []                      # all removed
    assert g.waiver_conflict(base, head, both, None) == []                      # the file deleted


def test_a_rule_change_may_not_add_or_edit_a_waiver_or_leave_a_file_that_is_not_an_object():
    base, head = {"R": (QUADRATIC,)}, {"R": (LINEAR,)}
    before = json.dumps({"R": W1})
    for after in (json.dumps({"R": W1, "S": W2}),             # an entry added
                  json.dumps({"R": W2}),                      # a reason edited
                  json.dumps({"R": W1 + " "}),                # one byte more
                  json.dumps({"S": W1}),                      # one removed and another added
                  "[]", "not json", '"R"'):
        assert g.waiver_conflict(base, head, before, after), after
    assert g.waiver_conflict(base, head, None, before)


def test_the_waivers_that_decide_are_the_tip_ones_minus_the_ids_the_head_removed():
    tip = {"A": W1, "B": W1, "NEW": W2}
    fork = {"A": W1, "B": W1}
    assert g.effective_waivers(tip, fork, {"B": W1}) == {"B": W1, "NEW": W2}      # A removed
    assert g.effective_waivers(tip, fork, {}) == {"NEW": W2}                      # both removed
    assert g.effective_waivers(tip, fork, dict(fork)) == tip                      # none removed
    assert g.effective_waivers(tip, fork, {"NEW": W2}) == {"NEW": W2}             # the head's own entries never add


def test_bounding_a_waived_rule_and_removing_its_waiver_is_one_pull_request():
    w = {"R": W1}
    waivers = g.effective_waivers(w, w, {})
    _, failures, _ = run({"R": (QUADRATIC,)}, {"R": (LINEAR,)}, waivers_base=waivers, waivers_head={},
                         growth_floor=1, ratio_floor=1)
    assert failures == []
    _, kept, _ = run({"R": (QUADRATIC,)}, {"R": (LINEAR,)}, waivers_base=w, waivers_head=w,
                     growth_floor=1, ratio_floor=1)
    assert any("does not trip" in f for f in kept)                    # the waiver left in place is still stale


def test_a_removed_waiver_is_no_longer_an_exception_for_a_rule_that_still_trips(monkeypatch):
    _by_shape(monkeypatch, {QUADRATIC: (1e-8, 2), r"a+c": (1e-8, 2)})
    w = {"R": W1}
    _, failures, _ = run({"R": (QUADRATIC,)}, {"R": (r"a+c",)}, waivers_base=g.effective_waivers(w, w, {}),
                         waivers_head={})
    assert failures and not any("does not trip" in f for f in failures)


def _two(rx):
    """PATTERNS for R1 and R2; each element of `rx` is one regex or a tuple of regexes."""
    return repr([{"id": f"R{n}", "regex": list(x) if isinstance(x, tuple) else [x]} for n, x in enumerate(rx, 1)])


def _fork(tmp_path, fork, tip=None, head=None, fork_w=None, tip_w=None, head_w=None):
    """A repo with a fork commit, a base branch that moved on (`tip`) and a pull request branch (`head`).

    Each of fork, tip and head is the pair of regexes of R1 and R2 at that commit; None keeps the
    previous one. The w arguments are the waiver file at that commit (None: unchanged, False: absent).
    Returns (repo, base_tip_sha, head_sha, fork_sha).
    """
    repo = tmp_path / "r"
    (repo / "sunglasses").mkdir(parents=True)
    _git(tmp_path, "init", "-q", "-b", "trunk", str(repo))
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")

    def commit(rx, w, msg):
        if rx is not None:
            (repo / "sunglasses" / "patterns.py").write_text("PATTERNS = " + _two(rx) + "\n")
        (repo / "sunglasses" / "mechanisms.py").write_text(MECH)
        f = repo / "tests" / "pattern_perf_waivers.json"
        if w is False:
            f.exists() and f.unlink()
        elif w is not None:
            f.parent.mkdir(exist_ok=True)
            f.write_text(json.dumps(w))
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "--allow-empty", "-m", msg)
        return _git(repo, "rev-parse", "HEAD")

    fork_sha = commit(fork, fork_w, "fork")
    _git(repo, "checkout", "-q", "-b", "pr")
    head_sha = commit(head or fork, head_w, "pr")
    _git(repo, "checkout", "-q", "trunk")
    tip_sha = commit(tip or fork, tip_w, "tip")
    return repo, tip_sha, head_sha, fork_sha


def test_cli_a_pull_request_that_bounds_a_waived_rule_and_removes_its_waiver_passes(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, (QUADRATIC, LINEAR), head=(LINEAR, LINEAR), fork_w={"R1": W1}, head_w={})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 0, r.stdout + r.stderr


def test_cli_a_pull_request_that_bounds_a_waived_rule_and_keeps_its_waiver_fails_as_stale(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, (QUADRATIC, LINEAR), head=(LINEAR, LINEAR), fork_w={"R1": W1})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 1 and "does not trip" in r.stdout


def test_cli_a_pull_request_that_removes_a_waiver_and_still_trips_fails(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, (QUADRATIC, LINEAR), head=(r"a+c", LINEAR), fork_w={"R1": W1}, head_w={})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 1 and "WAIVED" not in r.stdout and "growth" in r.stdout


def test_cli_a_rule_change_that_adds_a_waiver_still_fails(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, (QUADRATIC, LINEAR), head=(LINEAR, LINEAR), head_w={"R1": W1})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 1 and "pull request of its own" in r.stdout


def test_cli_a_rule_the_base_branch_changed_after_the_fork_is_not_charged_to_the_pull_request(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, (LINEAR, QUADRATIC), tip=(LINEAR, LINEAR), head=(r"read\s+tokens?", QUADRATIC))
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "changed 1, added 0" in r.stdout


def test_cli_a_waiver_the_base_branch_gained_after_the_fork_still_covers_the_pull_request(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, (LINEAR, LINEAR), head=(QUADRATIC, LINEAR), tip_w={"R1": W1})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "WAIVED" in r.stdout


def test_cli_names_the_merge_base_it_compared_with(tmp_path):
    repo, tip, head, fork = _fork(tmp_path, (LINEAR, LINEAR), tip=(LINEAR, r"read\s+tokens?"), head=(r"read\s+tokens?", LINEAR))
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 0 and f"merge-base {fork[:12]}" in r.stdout


def test_cli_without_a_merge_base_fails_and_says_to_fetch_the_history(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, (LINEAR, LINEAR))
    _git(repo, "checkout", "-q", "--orphan", "unrelated")
    _git(repo, "rm", "-rqf", ".")
    (repo / "sunglasses").mkdir()
    (repo / "sunglasses" / "patterns.py").write_text("PATTERNS = " + _two((LINEAR, LINEAR)) + "\n")
    (repo / "sunglasses" / "mechanisms.py").write_text(MECH)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "unrelated")
    other = _git(repo, "rev-parse", "HEAD")
    r = _cli(repo, "--base", tip, "--head", other)
    assert r.returncode == 1 and "fetch-depth" in r.stderr and "no merge-base" in r.stderr


def test_cli_a_shallow_clone_that_loses_the_fork_fails_and_never_falls_back_to_the_tip(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, (LINEAR, LINEAR), tip=(LINEAR, r"read\s+tokens?"), head=(r"read\s+tokens?", LINEAR))
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", "--no-single-branch", f"file://{repo}", str(shallow)],
                   check=True, capture_output=True)
    _git(shallow, "fetch", "-q", "--depth", "1", "origin", head)
    r = _cli(shallow, "--base", tip, "--head", head)
    assert r.returncode == 1 and "fetch-depth" in r.stderr


# ---------------------------------------------------------------- C249 r2: the review's cases

def test_a_removed_waiver_leaves_no_expression_of_its_rule_untimed(monkeypatch):
    # fixed times, so the test judges which expressions are selected and not the runner's clock
    _by_shape(monkeypatch, {QUADRATIC: (1e-8, 2), LINEAR: (1e-9, 1), r"read\s+tokens?": (1e-9, 1)})
    w = {"R": W1}
    base = {"R": (QUADRATIC, LINEAR)}
    head = {"R": (QUADRATIC, r"read\s+tokens?")}                     # only the second expression changed
    waivers = g.effective_waivers(w, w, {})
    _, kept, _ = run(base, head, waivers_base=waivers, waivers_head={}, removed_waivers=g.removed_waiver_ids(w, {}))
    assert kept and any(f.startswith("R r0/") and "growth" in f for f in kept)
    _, skipped, _ = run(base, head, waivers_base=waivers, waivers_head={})      # the id is not retimed: unchanged one skipped
    assert skipped == []


def test_cli_a_pull_request_that_removes_a_waiver_cannot_hide_an_unchanged_expression_that_still_trips(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, ((QUADRATIC, LINEAR), LINEAR), head=((QUADRATIC, r"read\s+tokens?"), LINEAR),
                               fork_w={"R1": W1}, head_w={})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 1 and "WAIVED" not in r.stdout and "growth" in r.stdout


def test_cli_the_same_pull_request_passes_when_every_expression_of_the_rule_is_bounded(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, ((QUADRATIC, LINEAR), LINEAR), head=((r"read\s+tokens?", r"read\s+tokens?"), LINEAR),
                               fork_w={"R1": W1}, head_w={})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_waiver_only_the_base_gained_still_gets_the_stale_check_when_the_head_never_had_it(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, (LINEAR, LINEAR), head=(r"read\s+tokens?", LINEAR), tip_w={"R1": W1})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 1 and "R1" in r.stdout and "does not trip" in r.stdout


def test_the_conflict_is_judged_against_the_fork_not_the_base_tip(tmp_path):
    # the base gained the waiver after the fork; a head that changes another rule and adds the same entry is
    # still adding it
    repo, tip, head, _ = _fork(tmp_path, (LINEAR, LINEAR), head=(LINEAR, r"read\s+tokens?"),
                               tip_w={"R1": W1}, head_w={"R1": W1})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 1 and "pull request of its own" in r.stdout


# ---------------------------------------------------------------- C249 r3: a removed waiver on a rule the head leaves unchanged

BOUNDED = (r"read\s+tokens?", r"read\s+tokens")


def test_a_removed_waiver_on_an_unchanged_rule_times_every_expression_of_it(monkeypatch):
    _by_shape(monkeypatch, {QUADRATIC: (1e-8, 2), LINEAR: (1e-9, 1)})
    w = {"R": W1}
    rules = {"R": (QUADRATIC, LINEAR)}
    waivers = g.effective_waivers(w, w, {})
    removed = g.removed_waiver_ids(w, {})
    rows, failures, _ = run(rules, rules, waivers_base=waivers, waivers_head={}, removed_waivers=removed)
    assert any(f.startswith("R r0/") for f in failures)
    assert {r["case"][:2] for r in rows} == {"r0", "r1"}
    assert not any(r["verdict"] == "WAIVED" for r in rows)


def test_a_removed_waiver_on_an_unchanged_rule_is_not_timed_without_the_removal_set():
    w = {"R": W1}
    rules = {"R": (QUADRATIC, LINEAR)}
    rows, failures, notes = run(rules, rules, waivers_base=g.effective_waivers(w, w, {}), waivers_head={})
    assert rows == [] and failures == [] and "timing 0 + 0 new" in notes[0]


def test_an_unchanged_rule_whose_waiver_was_removed_passes_when_every_expression_is_bounded():
    w = {"R": W1}
    rules = {"R": BOUNDED}
    _, failures, _ = run(rules, rules, waivers_base=g.effective_waivers(w, w, {}), waivers_head={},
                         removed_waivers=g.removed_waiver_ids(w, {}), growth_floor=1, ratio_floor=1)
    assert failures == []


def test_a_removed_waiver_for_a_rule_the_head_deletes_or_empties_has_nothing_to_time():
    w = {"R": W1}
    removed = g.removed_waiver_ids(w, {})
    for head in ({}, {"R": ()}):
        rows, failures, _ = run({"R": (QUADRATIC,)}, head, waivers_base=g.effective_waivers(w, w, {}),
                                waivers_head={}, removed_waivers=removed)
        assert rows == [] and failures == []


def test_cli_a_waiver_only_pull_request_cannot_unwaive_a_rule_that_still_trips(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, ((QUADRATIC, LINEAR), LINEAR), fork_w={"R1": W1}, head_w={})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 1 and "WAIVED" not in r.stdout and "R1 r0/" in r.stdout


def test_cli_an_unrelated_edit_does_not_hide_an_unchanged_rule_whose_waiver_was_removed(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, ((QUADRATIC, LINEAR), LINEAR), head=((QUADRATIC, LINEAR), r"read\s+tokens?"),
                               fork_w={"R1": W1}, head_w={})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 1 and "WAIVED" not in r.stdout and "R1 r0/" in r.stdout


def test_cli_a_waiver_only_pull_request_passes_when_the_rule_is_bounded(tmp_path):
    repo, tip, head, _ = _fork(tmp_path, (BOUNDED, LINEAR), fork_w={"R1": W1}, head_w={})
    r = _cli(repo, "--base", tip, "--head", head)
    assert r.returncode == 0, r.stdout + r.stderr


# ---------------------------------------------------------------- C260: no real-clock verdict below the production floors

@contextlib.contextmanager
def _watching():
    """A separate watch over the block. The module's own watch ignores the block, so a test of the watch can measure below the floors on purpose."""
    local = ClockWatch()
    with WATCH.silenced():
        local.install()
        try:
            yield local
        finally:
            local.uninstall()


def _measured(watch):
    return [v for v in watch.violations if v[2] == "measured"]


def _measure_at_zero_floors(timer):
    """A real measurement made by `timer` in a frame that holds floors of zero."""
    growth_floor = ratio_floor = 0
    return timer([re.compile(LINEAR)], "x" * 100)


def _run_counting_real_calls(monkeypatch, **floors):
    """One gate run on the real timer, with a count of the timer calls; returns the count."""
    calls = []

    def counting(*args, **kw):
        calls.append(1)
        return REAL_TIME_ONCE(*args, **kw)
    monkeypatch.setattr(g, "time_once", counting)
    run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, **floors)
    return len(calls)


@pytest.mark.parametrize("floors,flagged", [
    ((0, 0), True),
    ((1, 0), True),
    ((0, 1), True),
    ((PRODUCTION_FLOORS[0] / 2, PRODUCTION_FLOORS[1]), True),
    ((PRODUCTION_FLOORS[0], PRODUCTION_FLOORS[1] / 2), True),          # a ratio floor between zero and the production one
    ((1, 1), False),
    (PRODUCTION_FLOORS, False),
])
def test_the_watch_flags_every_real_measurement_made_below_the_production_floors(monkeypatch, floors, flagged):
    with _watching() as watch:
        calls = _run_counting_real_calls(monkeypatch, growth_floor=floors[0], ratio_floor=floors[1])
    assert calls
    assert len(_measured(watch)) == (calls if flagged else 0)          # one record per timer call
    assert {v[1] for v in _measured(watch)} == ({floors} if flagged else set())


def test_the_watch_ignores_a_measurement_made_outside_any_floor():
    with _watching() as watch:
        assert g.time_once([re.compile(LINEAR)], "x" * 100) is not None
    assert watch.violations == []


def test_the_watch_follows_code_not_names(monkeypatch):
    # a gate and a timer bound to other names before any test runs, called with floors of zero
    def through_the_other_name(*args, **kw):
        return TIMER_BY_ANOTHER_NAME(*args, **kw)
    monkeypatch.setattr(g, "time_once", through_the_other_name)
    with _watching() as watch:
        GATE_BY_ANOTHER_NAME({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, {}, {}, sizes=SMALL, added_sizes=SMALL_ADDED,
                             repeats=1, growth_floor=0, ratio_floor=0)
    assert _measured(watch)


def test_the_watch_sees_the_real_timer_put_back_after_fixed_samples(monkeypatch):
    _by_shape(monkeypatch, SHAPES)
    monkeypatch.setattr(g, "time_once", REAL_TIME_ONCE)
    with _watching() as watch:
        run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert _measured(watch)


def test_the_watch_sees_a_real_measurement_judged_at_zero_floors_by_a_helper():
    with _watching() as watch:
        seconds = g.median_time([re.compile(LINEAR)], "x" * 1000, 1)
        g.judge({1000: seconds, 2000: seconds}, {1000: seconds, 2000: seconds}, (1000, 2000),
                growth_floor=0, ratio_floor=0)
    assert [v for v in watch.violations if v[2] == "judged"]


def test_the_watch_compares_with_the_floors_of_the_file_load_not_the_module_now(monkeypatch):
    monkeypatch.setattr(g, "GROWTH_FLOOR_S", 0)
    monkeypatch.setattr(g, "RATIO_FLOOR_S", 0)
    with _watching() as watch:
        calls = _run_counting_real_calls(monkeypatch, growth_floor=0, ratio_floor=0)
    assert calls and len(_measured(watch)) == calls


def test_fixed_samples_are_never_flagged_whichever_came_first(monkeypatch):
    _by_shape(monkeypatch, SHAPES)                              # in place before the watch starts
    with _watching() as watch:
        run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
        _by_shape(monkeypatch, SHAPES)                          # and put in place again while it runs
        run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert watch.violations == []


def test_the_watch_sees_the_same_function_under_another_code_object():
    renamed = types.FunctionType(REAL_TIME_ONCE.__code__.replace(co_name="renamed"), g.__dict__,
                                 argdefs=REAL_TIME_ONCE.__defaults__)
    again_spec = importlib.util.spec_from_file_location("pattern_perf_gate_again", SCRIPT)
    again = importlib.util.module_from_spec(again_spec)
    again_spec.loader.exec_module(again)                  # the script executed a second time: new code objects
    assert again.time_once.__code__ is not REAL_TIME_ONCE.__code__
    local_names = types.FunctionType(
        REAL_TIME_ONCE.__code__.replace(co_varnames=tuple(f"v{i}" for i in range(len(REAL_TIME_ONCE.__code__.co_varnames)))),
        g.__dict__, argdefs=REAL_TIME_ONCE.__defaults__)          # the same bytecode with every local variable renamed
    with _watching() as watch:
        _measure_at_zero_floors(renamed)
        _measure_at_zero_floors(again.time_once)
        _measure_at_zero_floors(local_names)
    assert len(_measured(watch)) == 3


def test_the_watch_reads_the_floors_of_a_judge_whose_local_names_are_all_different():
    code = REAL_JUDGE.__code__
    renamed = types.FunctionType(code.replace(co_varnames=tuple(f"v{i}" for i in range(len(code.co_varnames)))),
                                 g.__dict__, argdefs=REAL_JUDGE.__defaults__)
    samples = {1000: 0.001, 2000: 0.002}
    with _watching() as watch:
        _measure_at_zero_floors(REAL_TIME_ONCE)                    # a real measurement in this test, so a verdict counts
        renamed(None, samples, (1000, 2000), 0, 0)
        assert watch.alive()
    assert [v[2] for v in watch.violations] == ["measured", "judged"]
    assert watch.violations[-1][1] == (0, 0)


def test_a_judge_whose_floors_cannot_be_read_is_recorded_and_the_watch_stays_on():
    unknown_shape = types.SimpleNamespace(f_code=REAL_JUDGE.__code__, f_locals={}, f_back=None)     # no floor to read
    with _watching() as watch:
        _measure_at_zero_floors(REAL_TIME_ONCE)
        watch._hook(unknown_shape, "call", None)
        assert watch.alive()
    assert [v[2] for v in watch.violations] == ["measured", "unreadable"]


def test_a_fixed_timer_that_is_called_time_once_is_not_the_real_timer(monkeypatch):
    def time_once(rxs, text, cap=None):
        return 0.001
    monkeypatch.setattr(g, "time_once", time_once)
    with _watching() as watch:
        run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert watch.violations == []


def test_the_watch_sees_a_measurement_made_by_a_worker_thread(monkeypatch):
    monkeypatch.delattr(g.signal, "setitimer")             # the timer's path that needs no signal, which a worker can run
    worker = threading.Thread(target=_measure_at_zero_floors, args=(REAL_TIME_ONCE,))
    with _watching() as watch:
        worker.start()
        worker.join()
    assert len(_measured(watch)) == 1
    assert [v for v in watch.violations if v[2] == "replaced"] == []          # a thread putting the hook in is not one


def test_a_thread_profiler_taken_out_for_a_while_is_refused():
    with _watching() as watch:
        threading.setprofile(None)                          # new threads would not be watched
        threading.setprofile(watch._hook)                   # putting the watch's own function back is not a replacement
    assert [v[2] for v in watch.violations] == ["replaced"]


def test_the_watch_hands_a_worker_threads_events_to_the_thread_profiler_it_found():
    seen = []

    def earlier(frame, event, arg):
        seen.append(threading.current_thread().name)
    worker = threading.Thread(target=lambda: None, name="clock-watch-worker")
    with WATCH.silenced():
        threading.setprofile(earlier)
        local = ClockWatch()
        local.install()
        try:
            worker.start()
            worker.join()
        finally:
            local.uninstall()
            threading.setprofile(WATCH._hook)
    assert "clock-watch-worker" in seen


def test_a_profiler_put_in_for_a_while_and_taken_out_again_is_refused():
    with _watching() as watch:
        kept = sys.getprofile()
        sys.setprofile(lambda *args: None)                  # another profiler, for a while
        _measure_at_zero_floors(REAL_TIME_ONCE)             # the watch is not called for this one
        sys.setprofile(kept)
        assert watch.alive()
    assert _measured(watch) == []
    assert [v[2] for v in watch.violations] == ["replaced"]          # putting the watch's own function back is not one


def test_a_call_made_before_the_floors_are_bound_is_neither_a_crash_nor_a_pass_for_the_next_one():
    def measures_before_it_holds_floors():
        REAL_TIME_ONCE([re.compile(LINEAR)], "x" * 100)
        growth_floor, ratio_floor = 0, 0
        REAL_TIME_ONCE([re.compile(LINEAR)], "x" * 100)
    with _watching() as watch:
        measures_before_it_holds_floors()
        assert watch.alive()
    assert [v[1] for v in _measured(watch)] == [(0, 0)]


def _earlier_profile(frame, event, arg):
    return None


def _another_profile(frame, event, arg):
    return None


@pytest.mark.parametrize("installed_again, default_changes", [(False, False), (True, False), (True, True)])
def test_a_worker_that_outlives_its_install_puts_back_the_profile_it_found(installed_again, default_changes):
    started, go, seen = threading.Event(), threading.Event(), []

    def work():
        started.set()
        go.wait(10)
        seen.append(sys.getprofile())
    with WATCH.silenced():
        threading.setprofile(_earlier_profile)
        local = ClockWatch()
        local.install()
        worker = threading.Thread(target=work)
        try:
            worker.start()
            assert started.wait(10)
            local.uninstall()
            if default_changes:
                threading.setprofile(_another_profile)          # what a later install finds is not what this worker found
            if installed_again:
                local.install()
            go.set()
            worker.join(10)
        finally:
            if installed_again:
                local.uninstall()
            go.set()
            threading.setprofile(WATCH._hook)
    assert seen == [_earlier_profile]
    assert local.violations == []


def test_a_fresh_worker_in_a_later_install_is_watched_after_an_earlier_worker_finished(monkeypatch):
    monkeypatch.delattr(g.signal, "setitimer")             # the timer's path that needs no signal, which a worker can run
    with WATCH.silenced():
        local = ClockWatch()
        for _ in range(2):
            local.install()
            try:
                worker = threading.Thread(target=_measure_at_zero_floors, args=(REAL_TIME_ONCE,))
                worker.start()
                worker.join(10)
            finally:
                local.uninstall()
    assert [v[1] for v in _measured(local)] == [(0, 0), (0, 0)]


def test_a_worker_left_over_from_an_earlier_install_is_not_recorded_in_a_later_one():
    started, go, done = threading.Event(), threading.Event(), threading.Event()

    def work():
        started.set()
        go.wait(10)
        sys.setprofile(_another_profile)                       # its own profile function, not the later install's business
        done.set()
    with WATCH.silenced():
        local = ClockWatch()
        local.install()
        worker = threading.Thread(target=work)
        try:
            worker.start()
            assert started.wait(10)
            local.uninstall()
            local.install()
            go.set()
            assert done.wait(10)
            worker.join(10)
        finally:
            local.uninstall()
            go.set()
    assert local.violations == []


def test_the_watch_hands_every_event_on_to_the_profiler_it_found():
    seen = []

    def earlier(frame, event, arg):
        seen.append((event, frame.f_code.co_name))
    with WATCH.silenced():
        module_hook = sys.getprofile()
        sys.setprofile(earlier)
        local = ClockWatch()
        local.install()
        seen.clear()                      # what `earlier` saw on its own, before the local watch took over
        try:
            (lambda: None)()
        finally:
            local.uninstall()
            sys.setprofile(module_hook)
    assert ("call", "<lambda>") in seen


LOW_LEVEL_THREAD_STARTERS = {"start_new_thread", "start_joinable_thread", "_start_new_thread", "_start_joinable_thread"}


def _low_level_thread_routes(tree):
    """Where a tree starts a thread below `threading`, which `threading.setprofile` does not reach."""
    found = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            found += [a.name for a in n.names if a.name.split(".")[0] == "_thread"]
        elif isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "_thread":
            found.append(n.module)
        elif isinstance(n, ast.Attribute) and n.attr in LOW_LEVEL_THREAD_STARTERS:
            found.append(n.attr)
        elif isinstance(n, ast.Name) and n.id in LOW_LEVEL_THREAD_STARTERS:
            found.append(n.id)
    return found


@pytest.mark.parametrize("source", [
    "import _thread\n",
    "from _thread import start_new_thread\n",
    "import threading\nthreading._start_new_thread(f, ())\n",
    "def f(t):\n    t.start_joinable_thread(g)\n",
])
def test_the_low_level_thread_guard_sees_each_way_in(source):
    assert _low_level_thread_routes(ast.parse(source))


def test_no_test_starts_a_thread_below_threading():
    assert _low_level_thread_routes(ast.parse(pathlib.Path(__file__).read_text())) == []


def test_no_test_measures_where_the_watch_cannot_see():
    tree = ast.parse(pathlib.Path(__file__).read_text())
    hooks = {"setup_module", "teardown_module", "setup_class", "teardown_class", "setup_function",
             "teardown_function", "setup_method", "teardown_method"}
    assert not {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)} & hooks
    floor_names = ("growth" + "_floor", "ratio" + "_floor")
    in_code_strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                       and any(name in n.value for name in floor_names) and any(c in n.value for c in "(=\n")]
    assert in_code_strings == []                    # no code string sets a floor; a child process is not watched at all


def test_a_watch_that_was_switched_off_is_noticed_and_put_back():
    with _watching() as local:
        assert local.alive()
        local._set_profile(None)                            # as the interpreter does at the recursion limit
        assert not local.alive() and local.violations == []
        local.reinstall()
        assert local.alive()
        sys.setprofile(None)                                # a test doing it is refused
        assert [v[2] for v in local.violations] == ["replaced"]
        local.reinstall()


RUNS_TO_THE_RECURSION_LIMIT = "test_a_source_that_fails_while_being_evaluated_is_a_failure"
MEASURING = {"run", "gate", "time_once", "median_time", "judge", "main", "_cli", "REAL_TIME_ONCE", "REAL_JUDGE",
             "GATE_BY_ANOTHER_NAME", "TIMER_BY_ANOTHER_NAME", "_run_counting_real_calls", "_measure_at_zero_floors"}


def _mentioned_from(tree, start):
    """Every name a function mentions, and what the functions it mentions by name mention in turn."""
    defs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    seen, mentioned, todo = set(), set(), [start]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for n in ast.walk(defs[name]):
            if isinstance(n, ast.Name):
                mentioned.add(n.id)
                if n.id in defs:
                    todo.append(n.id)
            elif isinstance(n, ast.Attribute):
                mentioned.add(n.attr)
                if n.attr in defs:                                  # a method is followed by its name, like a function
                    todo.append(n.attr)
    return mentioned


def test_the_reach_check_follows_helpers_and_attributes():
    tree = ast.parse("def a():\n    b()\n\n\ndef b():\n    c.time_once()\n")
    assert "time_once" in _mentioned_from(tree, "a")
    tree = ast.parse("class H:\n    def measure(self):\n        time_once()\n\n\ndef a():\n    H().measure()\n")
    assert "time_once" in _mentioned_from(tree, "a")


def test_the_test_that_runs_to_the_recursion_limit_reaches_no_gate_or_timer():
    tree = ast.parse(pathlib.Path(__file__).read_text())
    assert _mentioned_from(tree, RUNS_TO_THE_RECURSION_LIMIT) & MEASURING == set()


def test_the_fixtures_fail_a_test_that_measures_on_the_real_clock_below_the_production_floors(tmp_path):
    # the same fixtures, run by a separate pytest over planted tests: the real-clock test, the one whose fixture
    # measures during its teardown, the one that replaces the profiler and the one that loses the watch fail;
    # the fixed-sample test and the one that puts the watch back pass
    (tmp_path / "conftest.py").write_text(
        "import re\n"
        "import pytest\n"
        "from test_pattern_perf_gate import (_watch_the_clock_for_the_module,\n"
        "                                    _no_measurement_below_the_production_floors, run, LINEAR, QUADRATIC,\n"
        "                                    REAL_TIME_ONCE)\n\n\n"
        "@pytest.fixture(autouse=True)\n"
        "def _aaa_cleanup_that_measures(request):\n"
        "    if request.node.name == 'test_setup_measures':          # the setup of the test measures, outside any floors\n"
        "        REAL_TIME_ONCE([re.compile(LINEAR)], 'x' * 100)\n"
        "    yield\n"
        "    if request.node.name == 'test_late':\n"
        "        run({'R': (LINEAR,)}, {'R': (QUADRATIC,)})\n")
    (tmp_path / "test_planted.py").write_text(
        "import sys\n"
        "from test_pattern_perf_gate import (g, run, _by_shape, SHAPES, LINEAR, QUADRATIC, WATCH, REAL_TIME_ONCE,\n"
        "                                    _measure_at_zero_floors)\n\n"
        "SAVED_SETPROFILE = sys.setprofile          # a reference taken before any fixture replaces the name\n\n\n"
        "def _past_the_recursion_limit():\n"
        "    def f():\n"
        "        return f()\n"
        "    try:\n"
        "        f()\n"
        "    except RecursionError:\n"
        "        pass\n\n\n"
        "def test_real_clock():\n"
        "    run({'R': (LINEAR,)}, {'R': (QUADRATIC,)})\n\n\n"
        "def test_fixed_samples(monkeypatch):\n"
        "    _by_shape(monkeypatch, SHAPES)\n"
        "    run({'R': (LINEAR,)}, {'R': (QUADRATIC,)})\n\n\n"
        "def test_late():\n"
        "    pass\n\n\n"
        "def test_setup_measures():\n"
        "    g.judge({1000: 1e-3, 2000: 1e-3}, {1000: 1e-3, 2000: 1e-3}, (1000, 2000), 0, 0)\n\n\n"
        "def test_measures_through_a_saved_setter():\n"
        "    kept = sys.getprofile()\n"
        "    SAVED_SETPROFILE(None)\n"
        "    _measure_at_zero_floors(REAL_TIME_ONCE)\n"
        "    SAVED_SETPROFILE(kept)\n\n\n"
        "def test_clean():\n"
        "    pass\n\n\n"
        "def test_replaces_the_profiler():\n"
        "    kept = sys.getprofile()\n"
        "    sys.setprofile(lambda *args: None)\n"
        "    sys.setprofile(kept)\n\n\n"
        "def test_loses_the_watch():\n"
        "    _past_the_recursion_limit()\n\n\n"
        "def test_puts_the_watch_back():\n"
        "    _past_the_recursion_limit()\n"
        "    WATCH.reinstall()\n")
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    env["PYTHONPATH"] = str(pathlib.Path(__file__).parent)

    def pytest_run(*tests):
        return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                               *(f"test_planted.py::{t}" for t in tests)], cwd=tmp_path, env=env, capture_output=True, text=True)

    for test in ("test_real_clock", "test_late"):
        planted = pytest_run(test)
        assert planted.returncode != 0 and "below the production floors" in planted.stdout, test
    late_then_clean = pytest_run("test_late", "test_clean")            # the late record is reported by the next teardown
    assert late_then_clean.returncode != 0 and "below the production floors" in late_then_clean.stdout
    assert "test_planted.py::test_late (teardown)" in late_then_clean.stdout
    replaces = pytest_run("test_replaces_the_profiler")
    assert replaces.returncode != 0 and "sys.setprofile" in replaces.stdout
    judged_after_setup = pytest_run("test_setup_measures")           # a measurement made by a fixture of the same test counts
    assert judged_after_setup.returncode != 0 and "below the production floors" in judged_after_setup.stdout
    assert pytest_run("test_measures_through_a_saved_setter").returncode == 0          # a limit of the watch, stated in its docstring
    off = pytest_run("test_loses_the_watch")
    assert off.returncode != 0 and "switched off" in off.stdout
    for test in ("test_fixed_samples", "test_puts_the_watch_back"):
        assert pytest_run(test).returncode == 0, test
    # the next test is watched again after one that put the watch back
    again = pytest_run("test_puts_the_watch_back", "test_real_clock")
    assert again.returncode != 0 and "ERROR test_planted.py::test_real_clock" in again.stdout   # reported at teardown
    assert "below the production floors" in again.stdout and "test_planted.py::test_puts" not in again.stdout
    # the next test is watched again after one that lost it: it is reported for what it measured, not only for the lost watch
    after_loss = pytest_run("test_loses_the_watch", "test_real_clock")
    assert "ERROR test_planted.py::test_real_clock" in after_loss.stdout and "below the production floors" in after_loss.stdout
