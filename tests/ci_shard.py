"""Split one full-suite run into N parts that together are exactly the whole suite.

A CI leg sets CI_SHARD="i/n" (for example "1/2"). The run still collects every
test, then keeps the ones whose FILE belongs to part i and reports the rest as
deselected. Because the split is made on what pytest collected, and not on a
file list written beside it, no test can fall between the parts and none can
run twice: the kept counts of the n parts add up to the collected count.

Assignment is by file, largest first, each file to the lighter part, so the
result depends only on the collected file names and the table below. The table
holds measured seconds for the files that dominate the slowest interpreter;
every other file counts as DEFAULT_COST. A new slow file only makes the parts
less even, it never makes the split wrong.

One file is the exception. tests/test_negation_cues_and_lists.py holds about
two fifths of all collected tests, and its measured seconds swing between runs
by a factor of four (1372 s to 6009 s on the same interpreter), so no file-sized
slot can be balanced against it. It is split by test instead: a test goes to
part crc32(node id) % n + 1. Both parts then carry about an equal share of it
whatever it costs, and its cost drops out of the balance.

The deal is made on the node id and not on the test's position in the
collection, on purpose. The two parts are collected in two separate jobs, and
the order tests are collected in is not the same in both (parametrize lists
built from a directory listing come back in a different order on each runner).
A position-based deal then gives two jobs two different answers and some tests
run in neither part; a deal on the id gives one answer however the list is
ordered.
"""
import os
import zlib

DEFAULT_COST = 4

# Seconds from run 41633101898 (main d8630621cbeb), Python 3.14, both parts summed
# (setup + call + teardown per file, from pytest's per-test durations). Every file
# measured at 60 s or more is listed; DEFAULT_COST is the mean of the rest. Keys are
# collected paths, as pytest prints them. The negation file's entry is kept for the
# record only: SPLIT_BY_TEST takes it out of assign().
COST = {
    "tests/test_settings_validator.py": 1199,
    "tests/test_v056_matrix.py": 1001,
    "tests/test_environment_ast_validator.py": 942,
    "tests/test_structural_validators.py": 859,
    "tests/test_negation_cues_and_lists.py": 838,
    "tests/test_registry_redirect_validator.py": 647,
    "tests/test_benchmark_installed.py": 354,
    "tests/test_benchmark_negatives_truth.py": 236,
    "tests/test_pattern_perf_gate.py": 227,
    "tests/test_lab_b1_quadratic_whitespace_gate.py": 162,
    "tests/test_api_response_siblings.py": 150,
    "tests/test_extension_parity.py": 149,
    "tests/proxy/test_poisoned_listing_end_to_end.py": 126,
    "tests/test_real_corpus_fp.py": 119,
    "tests/test_gauntlet.py": 99,
    "tests/test_anchored_window_matching.py": 98,
    "tests/test_repair_v056.py": 87,
    "tests/proxy/test_artifact_review.py": 77,
    "tests/test_scan_repo_progress_and_dir.py": 66,
    "tests/test_repo_ladder_corpus.py": 62,
}


# Files whose tests are dealt out one by one instead of being given to one part.
SPLIT_BY_TEST = frozenset({"tests/test_negation_cues_and_lists.py"})


def parse(spec):
    """'i/n' -> (i, n). Anything else is an error: a typo must not run the whole suite."""
    try:
        i, n = (int(x) for x in spec.split("/"))
    except ValueError:
        raise ValueError(f"CI_SHARD must look like 1/2, got {spec!r}")
    if not (n >= 1 and 1 <= i <= n):
        raise ValueError(f"CI_SHARD {spec!r}: need 1 <= i <= n")
    return i, n


def assign(paths, n):
    """{path: part number 1..n} for the file-granular files, deterministic in
    the set of paths. Files in SPLIT_BY_TEST are left out: they have no one part."""
    load = [0] * n
    out = {}
    for p in sorted(set(paths) - SPLIT_BY_TEST, key=lambda p: (-COST.get(p, DEFAULT_COST), p)):
        k = min(range(n), key=lambda j: (load[j], j))
        out[p] = k + 1
        load[k] += COST.get(p, DEFAULT_COST)
    return out


def path_of(nodeid):
    return nodeid.split("::", 1)[0]


def select(items, spec):
    """(kept, dropped) for part spec over a list of collected items."""
    i, n = parse(spec)
    part = assign([path_of(it.nodeid) for it in items], n)
    kept, dropped = [], []
    for it in items:
        p = path_of(it.nodeid)
        if p in SPLIT_BY_TEST:
            mine = zlib.crc32(it.nodeid.encode()) % n + 1 == i
        else:
            mine = part[p] == i
        (kept if mine else dropped).append(it)
    return kept, dropped


def spec_from_env():
    return os.environ.get("CI_SHARD", "").strip()
