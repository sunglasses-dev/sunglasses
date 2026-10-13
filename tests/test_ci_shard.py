"""The two CI parts of the full suite must be exactly the suite.

The split lives in tests/ci_shard.py and is applied by tests/conftest.py when
CI_SHARD is set. These tests pin the properties the release gate relies on: no
test is lost, none runs twice, the same files always land in the same part,
a malformed setting fails loudly, and the cost table names real files.
"""
import pathlib
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


def test_a_file_is_never_split_across_parts():
    items = _items(_real_paths(), per=5)
    where = {}
    for i in (1, 2):
        for it in ci_shard.select(items, f"{i}/2")[0]:
            where.setdefault(ci_shard.path_of(it.nodeid), set()).add(i)
    assert all(len(v) == 1 for v in where.values())


def test_assignment_depends_only_on_the_set_of_files():
    paths = _real_paths()
    assert ci_shard.assign(paths, 2) == ci_shard.assign(list(reversed(paths)), 2)


def test_every_costed_file_exists():
    # A renamed slow file would silently count as a default-cost file.
    missing = [p for p in ci_shard.COST if not (ROOT / p).exists()]
    assert missing == []


def test_the_two_parts_are_within_ten_percent_by_cost():
    parts = ci_shard.assign(_real_paths(), 2)
    load = {1: 0, 2: 0}
    for p, k in parts.items():
        load[k] += ci_shard.COST.get(p, ci_shard.DEFAULT_COST)
    assert max(load.values()) <= 1.1 * min(load.values()), load


@pytest.mark.parametrize("bad", ["", "1", "0/2", "3/2", "a/b", "1/0", "1/2/3"])
def test_a_malformed_setting_is_an_error_not_a_full_run(bad):
    with pytest.raises(ValueError):
        ci_shard.parse(bad)
