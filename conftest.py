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
import re

import pytest

from sunglasses.engine import SunglassesEngine


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

