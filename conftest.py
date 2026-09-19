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
import contextlib
import signal
import threading

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

