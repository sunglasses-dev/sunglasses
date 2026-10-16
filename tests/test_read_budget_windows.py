"""The price of a search over the start windows of an anchored rule is looked up, not summed.

An anchored rule is searched only near its anchor terms, and the budget prices a search over
the windows at or after the place it resumes. That price used to walk every remaining window on
every question, and a walk over many covered hits asks once per hit, so the work of asking grew
with the square of the number of windows. The price now comes from a running sum of the whole
windows plus the two windows the stretch can cut, and these tests pin both that it is the same
price and that asking it does not grow with the number of windows.
"""
import bisect
import random
import re

import pytest

from sunglasses import engine as engine_module
from sunglasses.engine import SunglassesEngine

QUOTED_NEGATION = 'Never use "zorbit now" here. '
QUOTED_FRAMING = 'Our scanner detects examples "zorbit now". '


def _rule(rule_id):
    return {
        "id": rule_id, "name": rule_id, "category": "test", "severity": "high",
        "channel": ["message"], "keywords": [], "description": "test rule",
        "regex": [r"(?i)zorbit now"],
    }


def _reference_cost(budget, lo, hi):
    """The price as it was computed before: every window from the first that matters, one by one."""
    if budget.idle or hi < lo:
        return 0
    offsets = 0
    for index in range(bisect.bisect_left(budget.ends, lo), len(budget.windows)):
        begin, end = budget.windows[index]
        if begin > hi:
            break
        top = end + budget.reach if end < hi else hi
        offsets += min(top, budget.size) - max(begin, lo) + 1
    return offsets * budget.hit


def _windows(rng, size, count):
    """Disjoint sorted windows of start positions, the shape _anchor_plan returns."""
    cuts = sorted(rng.sample(range(size), 2 * count))
    return [(cuts[2 * i], cuts[2 * i + 1]) for i in range(count)]


@pytest.mark.parametrize("seed", range(40))
def test_the_price_over_windows_equals_the_sum_it_replaces(seed):
    rng = random.Random(seed)
    size = rng.randint(40, 600)
    windows = _windows(rng, size, rng.randint(1, min(12, size // 2)))
    reach = rng.randint(0, 40)
    budget = engine_module._ReadBudget(
        "anchored", re.compile(r"zorbit now"), None, "x" * size, 1024, 1 << 18,
        ("windows", windows, [w[1] for w in windows]), reach)
    for _ in range(300):
        lo = rng.randint(0, size + 3)
        hi = rng.choice((size, rng.randint(0, size + 3)))
        assert budget._cost(lo, hi) == _reference_cost(budget, lo, hi), (windows, reach, lo, hi)


def test_a_price_asked_inside_one_window_and_between_windows():
    windows = [(10, 20), (40, 50), (80, 90)]
    budget = engine_module._ReadBudget(
        "anchored", re.compile(r"zorbit now"), None, "x" * 120, 1024, 1 << 18,
        ("windows", windows, [20, 50, 90]), 5)
    for lo, hi in [(0, 120), (15, 18), (21, 39), (45, 85), (50, 80), (91, 120), (119, 120), (0, 0)]:
        assert budget._cost(lo, hi) == _reference_cost(budget, lo, hi), (lo, hi)


class _Counted(list):
    def __init__(self, items, counts):
        super().__init__(items)
        self._counts = counts

    def __getitem__(self, key):
        if isinstance(key, int):
            self._counts[0] += 1
        return super().__getitem__(key)


@pytest.mark.parametrize("unit,rule_id", [
    (QUOTED_NEGATION, "GLS-TEST-001"),
    (QUOTED_FRAMING, "GLS-MECH-TEST-001"),
])
def test_covered_hits_in_separate_windows_do_not_revisit_the_windows(monkeypatch, unit, rule_id):
    counts = [0]
    real_init = engine_module._ReadBudget.__init__

    def init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        if self.windows is not None:
            self.windows = _Counted(self.windows, counts)

    monkeypatch.setattr(engine_module._ReadBudget, "__init__", init)
    rule = _rule(rule_id)
    rule.update(anchor_terms=["zorbit"], anchor_span=10)
    padded = unit + "padding " * 8
    visits = []
    for copies in (500, 1000, 2000, 4000):
        counts[0] = 0
        eng = SunglassesEngine(patterns=[rule], mechanisms=False)
        result = eng.scan(padded * copies, "message")
        assert result.decision == "allow_redacted", (copies, result.decision)
        visits.append(counts[0])
    # Work that grows with the number of hits: every doubling at most doubles it (plus slack).
    # The walk used to quadruple it (0.5M, 2.0M, 8.0M, 32M visits at 1k to 8k hits).
    for before, after in zip(visits, visits[1:]):
        assert after <= 2.3 * before + 20, visits
    assert visits[-1] < 40 * 4000, visits
