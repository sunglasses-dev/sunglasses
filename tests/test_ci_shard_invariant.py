"""The CI parts add up to the suite on a real run, quick or full.

The release gate counts the two CI parts and expects kept 1 + kept 2 + M to be
the collected total, and each part's kept set to be the other's dropped set
less M. M is the number of tests the run's own `-m` expression deselects. It
is not part of the split: both parts drop those tests, so they sit in neither
part's kept count. On a quick run (`-m "not full_matrix"`) M is the number of
`full_matrix` tests; on a full run M is 0.

tests/test_ci_shard.py pins the split on made-up items. These tests run pytest
itself on a few real files, so the marker deselect and the CI_SHARD deselect
meet the way they do in CI. The files hold the `full_matrix` tests
(tests/test_v056_matrix.py, tests/test_ci_gate.py) and the split's own tests.
"""
import os
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILES = ["tests/test_ci_gate.py", "tests/test_v056_matrix.py", "tests/test_ci_shard.py"]
QUICK = ["-m", "not full_matrix"]
FULL = []


def _collect(shard, marker_args):
    """(kept node ids, deselected count) of one pytest collection over FILES."""
    env = dict(os.environ)
    env.pop("CI_SHARD", None)
    if shard:
        env["CI_SHARD"] = shard
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         *marker_args, *FILES],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300,
    )
    assert out.returncode == 0, out.stdout[-2000:] + out.stderr[-2000:]
    ids = [ln for ln in out.stdout.splitlines() if "::" in ln]
    m = re.search(r"(\d+)(?:/(\d+))? tests? collected(?: \((\d+) deselected\))?", out.stdout)
    assert m, out.stdout[-500:]
    kept = int(m.group(1))
    assert kept == len(ids)
    return set(ids), int(m.group(3) or 0)


@pytest.fixture(scope="module")
def runs():
    return {
        (name, shard): _collect(shard, args)
        for name, args in (("quick", QUICK), ("full", FULL))
        for shard in (None, "1/2", "2/2")
    }


@pytest.mark.parametrize("name", ["quick", "full"])
def test_the_two_parts_plus_the_marker_deselects_are_the_suite(runs, name):
    whole, m_whole = runs[(name, None)]
    one, d1 = runs[(name, "1/2")]
    two, d2 = runs[(name, "2/2")]
    marker_deselected = m_whole
    total = len(whole) + marker_deselected
    assert one.isdisjoint(two), "a test ran in both parts"
    assert len(one) + len(two) + marker_deselected == total
    assert one | two == whole, "a test selected by -m ran in neither part"
    # Each part drops the other part's tests, plus the marker deselects (M).
    assert d1 == len(two) + marker_deselected
    assert d2 == len(one) + marker_deselected


def test_a_quick_run_deselects_the_full_matrix_tests_and_a_full_run_none():
    # Guard against the quick/full distinction going quiet: if the marker were
    # gone, M would be 0 on both runs and the two checks above would agree
    # without ever exercising the offset.
    _, m_quick = _collect(None, QUICK)
    _, m_full = _collect(None, FULL)
    assert m_quick > 0
    assert m_full == 0
