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

DEFAULT_COST = 6

# Seconds on the slowest interpreter in the matrix (3.12), from a green full
# run's per-test durations: run 39015698884 (main after the prefilter-table
# change), both 3.12 parts, setup + call + teardown summed per file. Every file
# measured at 60 s or more is listed; DEFAULT_COST is the mean of the rest.
# Keys are collected paths, as pytest prints them. The negation file's entry is
# kept for the record only: SPLIT_BY_TEST takes it out of assign().
COST = {
    "tests/test_negation_cues_and_lists.py": 6009,
    "tests/test_v056_matrix.py": 1198,
    "tests/test_api_response_siblings.py": 512,
    "tests/test_repair_v056.py": 238,
    "tests/test_benchmark_installed.py": 228,
    "tests/test_defensive_framing_later_hits.py": 210,
    "tests/test_lab_b1_quadratic_whitespace_gate.py": 205,
    "tests/test_directive_and_hidden_text_case_matrix.py": 202,
    "tests/test_benchmark_negatives_truth.py": 200,
    "tests/test_prefilter_table.py": 164,
    "tests/test_a_control_character_beside_a_negated_quote_changes_nothing.py": 148,
    "tests/test_regex_prefilter.py": 146,
    "tests/test_anchored_window_matching.py": 119,
    "tests/test_hidden_text_rule_on_every_start_tag.py": 109,
    "tests/test_ai_addressed_directive_rules.py": 109,
    "tests/proxy/test_artifact_review.py": 108,
    "tests/test_gauntlet.py": 101,
    "tests/test_enc_alt_210_run_boundary.py": 92,
    "tests/test_proxy_state_dir_obstruction.py": 89,
    "tests/test_real_corpus_fp.py": 82,
    "tests/test_repo_ladder_corpus.py": 61,
    "tests/test_prefilter_branch_coverage.py": 61,
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
