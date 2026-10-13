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
"""
import os

DEFAULT_COST = 28

# Seconds on the slowest interpreter in the matrix, from a green full run's
# per-test durations. Keys are collected paths, as pytest prints them.
COST = {
    "tests/test_defensive_framing_later_hits.py": 3997,
    "tests/test_api_response_siblings.py": 1509,
    "tests/test_negation_blank_run_in_match.py": 907,
    "tests/test_directive_and_hidden_text_case_matrix.py": 800,
    "tests/test_enc_alt_210_run_boundary.py": 485,
    "tests/test_leading_whitespace_run_cost.py": 282,
    "tests/test_firewall_fuzzy.py": 159,
}


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
    """{path: part number 1..n}, deterministic in the set of paths."""
    load = [0] * n
    out = {}
    for p in sorted(set(paths), key=lambda p: (-COST.get(p, DEFAULT_COST), p)):
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
    kept = [it for it in items if part[path_of(it.nodeid)] == i]
    dropped = [it for it in items if part[path_of(it.nodeid)] != i]
    return kept, dropped


def spec_from_env():
    return os.environ.get("CI_SHARD", "").strip()
