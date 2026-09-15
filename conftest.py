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

