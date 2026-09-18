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
import os
import sys
import pytest

from sunglasses.engine import SunglassesEngine


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



# ── the 3.12 stall, and the instrument that names its line ──────────────────
#
# R-CI-312-FAULTHANDLER (T9, 2026-09-18). The 3.12 integrity leg carries 41
# fixed waits against the 3.13 leg of the same commit, measured twice on two
# commits: 35 single and 3 double both times, unit 86.45 s then 82.44 s. The
# COUNT is invariant and the DURATION is not, so it is not a hardcoded timeout;
# and #189 showed engine construction is 2-3.7 s on every interpreter, so it is
# not CPU work in the engine either.
#
# Three instruments have failed to name it, each for a stated reason:
#   --durations=25  could not COUNT them (22 of its 25 rows sat at the ceiling)
#   --durations=0   counted and PLACED them, and says nothing about why
#   strace, 38 rows those rows in isolation do not reproduce the wait at all
#
# So this asks the one question none of those could: WHERE IS THE INTERPRETER
# STANDING when it waits. `dump_traceback_later(60, repeat=True)` prints every
# thread's Python stack every time 60 s elapse without the timer being reset,
# which names the LINE rather than the syscall, and shows a wait on a child as
# the parent parked in `wait4`/`communicate` just as clearly.
#
# IT IS OFF UNLESS ASKED. The workflow sets SUNGLASSES_STALL_TRACE on the 3.12
# leg and nowhere else; with the variable unset this block does nothing at all,
# so every other run -- local, fast lane, the other five matrix legs -- is
# byte-for-byte the run it was before.
#
# The dumps go to stderr and are kept open for the life of the process: the file
# object must outlive this function or the timer writes into a closed
# descriptor, which is a way of turning a diagnostic into a crash.
if os.environ.get("SUNGLASSES_STALL_TRACE"):  # pragma: no cover - CI only
    import faulthandler as _faulthandler

    _STALL_SECONDS = float(os.environ.get("SUNGLASSES_STALL_SECONDS", "60"))
    # A FILE, NOT A STREAM THE RUN OWNS. Both obvious choices lose the dump:
    # `sys.stderr` is replaced by pytest's capture object, and even a dup of
    # fd 2 taken here is redirected afterwards by pytest's fd-level capture. I
    # measured both -- the timer fired, the stack was written, and nothing
    # reached the log. That failure mode reads exactly like "no stall
    # occurred", which is the one reading this instrument must never produce by
    # accident.
    #
    # `-s` would also work and is rejected: turning capture off for a 2-hour
    # suite changes what the run does, and an instrument that perturbs the thing
    # it measures is not one I want pointed at a timing mystery.
    #
    # So the dumps go to their own file, the workflow uploads it, and the handle
    # stays open for the life of the process because a timer firing into a
    # closed descriptor turns a diagnostic into a crash.
    _stall_path = os.environ.get("SUNGLASSES_STALL_FILE", "stall-trace.txt")
    _stall_stream = open(_stall_path, "w", buffering=1)
    _faulthandler.enable(file=_stall_stream, all_threads=True)
    _faulthandler.dump_traceback_later(_STALL_SECONDS, repeat=True,
                                       file=_stall_stream, exit=False)
    print(f"[stall-trace] armed: every thread's stack after "
          f"{_STALL_SECONDS:.0f}s of no progress, repeating -> {_stall_path}",
          file=_stall_stream, flush=True)
