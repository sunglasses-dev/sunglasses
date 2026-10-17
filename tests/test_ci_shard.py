"""The two CI parts of the full suite must be exactly the suite.

The split lives in tests/ci_shard.py and is applied by tests/conftest.py when
CI_SHARD is set. These tests pin the properties the release gate relies on: no
test is lost, none runs twice, the same files always land in the same part,
a malformed setting fails loudly, and the cost table names real files.
"""
import os
import pathlib
import subprocess
import sys
import types

import pytest

import ci_shard

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _items(paths, per=3):
    return [types.SimpleNamespace(nodeid=f"{p}::t{k}") for p in paths for k in range(per)]


def _real_paths():
    paths = [p.relative_to(ROOT).as_posix() for p in (ROOT / "tests").rglob("test_*.py")]
    paths += [p.name for p in ROOT.glob("test_*.py")]
    return sorted(paths)


@pytest.mark.parametrize("n", [1, 2, 3])
def test_parts_are_a_partition_of_the_collected_items(n):
    items = _items(_real_paths())
    seen = []
    for i in range(1, n + 1):
        kept, dropped = ci_shard.select(items, f"{i}/{n}")
        assert len(kept) + len(dropped) == len(items)
        seen.extend(it.nodeid for it in kept)
    assert sorted(seen) == sorted(it.nodeid for it in items)
    assert len(seen) == len(set(seen))


def test_a_file_is_never_split_across_parts_except_the_one_dealt_by_test():
    items = _items(_real_paths(), per=5)
    where = {}
    for i in (1, 2):
        for it in ci_shard.select(items, f"{i}/2")[0]:
            where.setdefault(ci_shard.path_of(it.nodeid), set()).add(i)
    whole = {p for p, v in where.items() if len(v) == 1}
    assert set(where) - whole == set(ci_shard.SPLIT_BY_TEST)
    assert all(len(where[p]) == 2 for p in ci_shard.SPLIT_BY_TEST)


@pytest.mark.parametrize("n", [1, 2, 3])
def test_a_file_dealt_by_test_is_collected_exactly_once_across_the_parts(n):
    f = "tests/test_negation_cues_and_lists.py"
    assert f in ci_shard.SPLIT_BY_TEST
    # ids with brackets and repeats, in a mixed order, as parametrize makes them
    items = [types.SimpleNamespace(nodeid=f"{f}::t[{k % 7}-{k}]") for k in range(101)]
    items += _items(["tests/test_other.py"])
    full = [it.nodeid for it in items if ci_shard.path_of(it.nodeid) == f]
    halves = [[it.nodeid for it in ci_shard.select(items, f"{i}/{n}")[0]
               if ci_shard.path_of(it.nodeid) == f] for i in range(1, n + 1)]
    assert sum(len(h) for h in halves) == len(full)
    assert set().union(*map(set, halves)) == set(full)
    assert sorted(x for h in halves for x in h) == sorted(full)
    assert max(map(len, halves)) - min(map(len, halves)) <= 1
    # part i holds the tests whose collected index k has k % n == i - 1
    assert halves[0] == full[0::n]


def test_the_dealt_file_does_not_move_the_other_files():
    paths = _real_paths()
    rest = [p for p in paths if p not in ci_shard.SPLIT_BY_TEST]
    assert ci_shard.assign(paths, 2) == ci_shard.assign(rest, 2)


def test_assignment_depends_only_on_the_set_of_files():
    paths = _real_paths()
    assert ci_shard.assign(paths, 2) == ci_shard.assign(list(reversed(paths)), 2)


def test_every_costed_file_exists():
    # A renamed slow file would silently count as a default-cost file.
    missing = [p for p in ci_shard.COST if not (ROOT / p).exists()]
    assert missing == []


def test_the_two_parts_are_within_ten_percent_by_cost():
    parts = ci_shard.assign(_real_paths(), 2)
    # a dealt file adds the same share to every part, so it is left out of the sum
    load = {1: 0, 2: 0}
    for p, k in parts.items():
        load[k] += ci_shard.COST.get(p, ci_shard.DEFAULT_COST)
    assert max(load.values()) <= 1.1 * min(load.values()), load


@pytest.mark.parametrize("bad", ["", "1", "0/2", "3/2", "a/b", "1/0", "1/2/3"])
def test_a_malformed_setting_is_an_error_not_a_full_run(bad):
    with pytest.raises(ValueError):
        ci_shard.parse(bad)


def test_the_part_is_not_inherited_by_a_test():
    # On a CI leg CI_SHARD is set when the run starts; once the part is chosen
    # it is removed, so a pytest a test starts collects the whole suite.
    assert "CI_SHARD" not in os.environ


def test_a_sharded_run_removes_the_part_before_tests_run():
    node = "tests/test_ci_shard.py::test_the_part_is_not_inherited_by_a_test"
    env = dict(os.environ, CI_SHARD="1/2")
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", node],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=300)
    assert out.returncode == 0 and "1 passed" in out.stdout, out.stdout[-2000:]
