"""Pytest fixtures for SUNGLASSES test suite.

ONE ENGINE PER MODULE, NOT ONE PER TEST, WHERE THAT IS HONEST.

Compiling the full ruleset costs about 1.9 s locally and roughly 3 s on a
starved runner. A helper that builds an engine inside itself pays that once per
TEST, so a 78-test module spends two minutes compiling the same rules 78 times
and scanning for under a second. That is most of why #164's integrity job hit
the 180 minute cap at 30%.

The fix is a module-scoped engine, and the honest part is not the fixture, it is
proving the sharing is safe and keeping it that way:

  `shared_engine`   built once per module. For tests that only SCAN.
  `engine`          built per test, unchanged. For tests that MUTATE an engine,
                    toggle extractors or edit config, where sharing would make
                    one test's setup another test's surprise.
  `engine_budget`   a runtime guard. It counts real constructor calls during a
                    module and fails if a test builds its own engine anyway, so
                    the next author cannot quietly reintroduce 78 compiles.

`engine_budget` counts the CONSTRUCTOR rather than grepping the source for
`SunglassesEngine(`, because a source grep answers a question about text and
the question here is about calls. A comment, a docstring or a string literal
naming the class is not a compile; a helper three files away that builds one is.
"""
import atexit
import collections
import contextlib
import os
import re
import signal
import threading
import time

import pytest

from sunglasses.engine import SunglassesEngine


@contextlib.contextmanager
def _fails_rather_than_hangs(seconds):
    """Bound a BLOCKING call, so a row that would hang fails instead.

    A wall-clock assertion written after the call cannot do this, and that is
    not a nitpick -- it is the whole difference. `assert elapsed < N` only runs
    once the call has already returned, so against a genuinely stuck operation
    it is never reached and the row hangs until something outside kills it.
    Measured while writing this: a row whose deadline was mutated away sat for
    180 s with a 60 s "backstop" two lines below it, untouched.

    So the bound is armed BEFORE the call and interrupts it. The number is a
    hang guard and nothing else -- it is not a performance assertion, and it is
    set far above anything a loaded runner produces, because the thing these
    rows prove is the RECORDED OUTCOME and a clock next to that outcome can
    only add a way to fail while the outcome is right.

    SIGALRM and the main thread are required rather than optional. A guard
    that quietly becomes a no-op where it cannot arm is a check that skips
    itself, which is worse than no check: every row using it would keep
    passing and none of them would be bounded. The proxy suites that use this
    already require POSIX process groups, so there is no platform where the
    rows run and the guard could not.
    """
    if not hasattr(signal, "SIGALRM"):
        raise RuntimeError(
            "fails_rather_than_hangs needs SIGALRM; refusing to run unbounded "
            "rather than pass an unguarded row")
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError(
            "fails_rather_than_hangs must arm on the main thread; refusing to "
            "run unbounded rather than pass an unguarded row")

    def fire(_signum, _frame):
        raise TimeoutError(
            f"blocked for more than {seconds}s; the operation this row bounds "
            f"did not return, so the deadline it exists to prove never fired")

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@pytest.fixture
def fails_rather_than_hangs():
    """The guard above, as a fixture.

    A fixture rather than an import because `from conftest import ...` does not
    mean what it looks like: with a `conftest.py` in `tests/` as well, the name
    resolves to the NEARER one and the import fails at collection. pytest
    injects fixtures by name from the whole conftest chain, which is the
    mechanism that actually exists for sharing this.
    """
    return _fails_rather_than_hangs


# ── EVERY re.compile, TIMED, WHEN ASKED AND NEVER OTHERWISE ────────────────
#
# The question (CI_312_LEG.md §12): the 3.12 integrity leg carries 41 fixed
# waits against 3.13 on the same commit, counted twice, and the patch version
# is eliminated. Construction is where the frames land (§11), and on the box
# construction is 71% `re.compile` -- 3,075 calls over 2,986 distinct sources
# against a 512-entry cache, so nearly everything recompiles every time.
#
# That is a MULTIPLIER, not an answer. Locally 3.12 and 3.13 build within 4%,
# so this box cannot say why CI differs. But if per-compile cost is what
# differs on that runner, it is multiplied by 3,075 per construction. This
# measures exactly that, on both legs, and the 3.13 leg is the control: a
# difference visible on both is not the 3.12 gap.
#
# A FILE, NOT A STREAM. #193 measured that pytest replaces sys.stderr and
# redirects a dup of fd 2 as well, so a diagnostic written to either is lost
# and reads afterwards exactly like "nothing happened".
#
# The wrapper is a perf_counter pair around the original call and nothing else.
# Its own overhead is reported in the artifact rather than asserted to be
# small, so a reader can subtract it instead of trusting it.
if os.environ.get("SUNGLASSES_COMPILE_TIMER"):  # pragma: no cover - CI only
    _TIMER_PATH = os.environ["SUNGLASSES_COMPILE_TIMER"]
    _TOTALS = collections.Counter()
    _COUNTS = collections.Counter()
    _WALL = {"in_compile": 0.0, "calls": 0}
    _original_compile = re.compile

    def _timed_compile(pattern, flags=0):
        start = time.perf_counter()
        try:
            return _original_compile(pattern, flags)
        finally:
            spent = time.perf_counter() - start
            key = pattern if isinstance(pattern, str) else repr(pattern)
            _TOTALS[key[:200]] += spent
            _COUNTS[key[:200]] += 1
            _WALL["in_compile"] += spent
            _WALL["calls"] += 1

    re.compile = _timed_compile

    @atexit.register
    def _dump_compile_times():  # pragma: no cover - CI only
        with open(_TIMER_PATH, "w") as handle:
            handle.write(f"python {os.sys.version.split()[0]}\n")
            handle.write(f"re._MAXCACHE {getattr(re, '_MAXCACHE', '?')}\n")
            handle.write(f"total re.compile calls {_WALL['calls']}\n")
            handle.write(f"distinct sources {len(_TOTALS)}\n")
            handle.write(f"seconds inside re.compile {_WALL['in_compile']:.3f}\n")
            handle.write("\n-- top 50 sources by TOTAL seconds --\n")
            handle.write(f"{'total_s':>9} {'calls':>7} {'per_call_ms':>12}  source\n")
            for source, total in _TOTALS.most_common(50):
                n = _COUNTS[source]
                handle.write(f"{total:9.3f} {n:7d} {1000 * total / n:12.4f}  "
                             f"{source[:110]!r}\n")


# ── THE REGEX CACHE THE ENGINE ASSUMES AND DOES NOT GET ────────────────────
#
# `engine.py:457` says "re.compile caches, so two rules sharing a source share
# the object". That is true of two rules and false of this pattern database.
# Measured on one default construction:
#
#     re.compile calls per construction   3,075
#     DISTINCT regex sources              2,986
#     re._MAXCACHE (CPython default)        512   <- holds 17% of them
#
# So the cache is full and evicting before the engine has finished building
# once, and nothing survives to the next construction. The consequence is not
# subtle: 71% of a build is spent inside re.compile (1.376 s of 1.948 s), and a
# SECOND engine in the same process costs the same as the first --
# 1.912 s then 1.938 s. The cache buys nothing at this scale.
#
# Raising it changes that and nothing else:
#
#     repeat construction, _MAXCACHE=512     1.938 s
#     repeat construction, _MAXCACHE=4096    0.575 s   (70% faster)
#
# Identical on 3.12 and 3.13, and the bump was verified to take effect on
# 3.11 through 3.14 (the cache really does grow past 512). 3.9 and 3.10 are in
# the CI matrix and are not installed here, so the guard below is written to
# do nothing rather than fail if the private name ever goes away.
#
# THIS IS A TEST-ONLY MEASURE AND NOT THE REPAIR. It sets a CPython private
# from the suite, which is acceptable here because it changes only how fast the
# tests build engines, and unacceptable as a product fix: the real repair is
# for the engine to own a compiled-regex cache keyed by (source, flags) across
# instances, and to correct that comment in the same change. Filed separately.
#
# ON BY DEFAULT, because a saving the suite has to opt into is a saving the
# suite will not get. Set SUNGLASSES_TEST_RE_CACHE=off to measure without it.
_RE_CACHE_WANTED = 4096
if os.environ.get("SUNGLASSES_TEST_RE_CACHE", "on").strip().lower() not in (
        "0", "off", "false", "no"):
    if hasattr(re, "_MAXCACHE") and re._MAXCACHE < _RE_CACHE_WANTED:
        re._MAXCACHE = _RE_CACHE_WANTED


@pytest.fixture
def engine():
    """A fresh engine per test. For tests that mutate one.

    Kept function-scoped deliberately. Anything that changes an engine's
    config, rules or extractors must not hand the next test a modified one.
    """
    return SunglassesEngine()


@pytest.fixture(scope="module")
def shared_engine():
    """One engine for the whole module. For tests that only scan.

    Safe exactly when the tests using it treat the engine as read-only. The
    statelessness control each converted module carries is what establishes
    that, by running the module's own fixtures twice in two different orders
    through ONE engine and requiring identical findings.
    """
    return SunglassesEngine()


@pytest.fixture(scope="module")
def engine_budget():
    """Fail the module if it constructs more engines than it declared.

    Usage, in a converted module:

        @pytest.fixture(scope="module", autouse=True)
        def _budget(shared_engine, engine_budget):
            engine_budget(0)

    Request `shared_engine` FIRST. Fixtures in a signature are set up before the
    body runs, so that forces the module's one engine to exist before counting
    starts. Without it the shared engine is charged to the budget meant to catch
    the unshared ones, and the guard fails on a correctly converted module.

    Zero means every test in the module takes a fixture. The count is of real
    constructor calls, including ones made inside helpers, which is the
    property that actually costs the time.
    """
    original = SunglassesEngine.__init__
    state = {"built": 0, "allowed": None}

    def counted(self, *args, **kwargs):
        state["built"] += 1
        return original(self, *args, **kwargs)

    def declare(allowed):
        state["allowed"] = allowed
        # Only start counting AFTER the module's own module-scoped fixtures
        # have been built, so the shared engine is not charged to the budget.
        state["built"] = 0
        SunglassesEngine.__init__ = counted

    yield declare

    SunglassesEngine.__init__ = original
    if state["allowed"] is not None and state["built"] > state["allowed"]:
        pytest.fail(
            f"this module constructed {state['built']} engine(s) during its "
            f"tests, and declared a budget of {state['allowed']}. Each one "
            f"compiles the full ruleset, about 1.9 s locally and 3 s on a "
            f"runner. Take `shared_engine` if the test only scans, or `engine` "
            f"if it genuinely needs its own, and raise the declared budget in "
            f"the same commit if the extra engine is deliberate.")

