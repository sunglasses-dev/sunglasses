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

DEFAULT_COST = 9

# Seconds on the slowest interpreter in the matrix (3.12), from a green full
# run's per-test durations: run 38357184575, both 3.12 parts, setup + call +
# teardown summed per file. Every file measured at 60 s or more is listed;
# DEFAULT_COST is the mean of the rest. Keys are collected paths, as pytest
# prints them.
COST = {
    "tests/test_defensive_framing_later_hits.py": 3602,
    "tests/test_v056_matrix.py": 2076,
    "tests/test_regex_prefilter.py": 1590,
    "tests/test_api_response_siblings.py": 1343,
    "tests/test_negation_blank_run_in_match.py": 1291,
    "tests/test_directive_and_hidden_text_case_matrix.py": 707,
    "tests/test_enc_alt_210_run_boundary.py": 435,
    "tests/test_ai_addressed_directive_rules.py": 384,
    "tests/test_repair_v056.py": 335,
    "tests/test_lab_a1_folded_regex_lane.py": 297,
    "tests/test_hidden_text_rule_on_every_start_tag.py": 277,
    "tests/test_leading_whitespace_run_cost.py": 252,
    "tests/test_sd_api_siblings.py": 240,
    "tests/test_benchmark_installed.py": 232,
    "tests/test_benchmark_negatives_truth.py": 220,
    "tests/test_lab_b1_quadratic_whitespace_gate.py": 172,
    "tests/test_firewall_fuzzy.py": 143,
    "tests/test_anchored_window_matching.py": 136,
    "tests/test_mcp_manifest_poisoning.py": 129,
    "tests/proxy/test_artifact_review.py": 128,
    "tests/test_input_cap.py": 124,
    "tests/test_proxy_state_dir_obstruction.py": 116,
    "tests/test_mcp_engine_lifetime.py": 109,
    "tests/test_sync_stats_languages.py": 107,
    "tests/test_gauntlet.py": 101,
    "tests/test_real_corpus_fp.py": 78,
    "tests/test_cli_file_routing.py": 74,
    "tests/test_negation_later_hits_round11.py": 67,
    "tests/test_negation_later_hits_round8.py": 66,
    "tests/test_dogfood_bugs.py": 62,
    "tests/test_stacked_lookaheads.py": 61,
    "tests/test_receipts_log_missing_and_run_jsonl.py": 61,
    "tests/test_prefilter_branch_coverage.py": 61,
    "tests/test_defensive_framing_window_edge.py": 60,
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
