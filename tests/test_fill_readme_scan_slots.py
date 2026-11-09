"""The README's scan-speed table is slots; the fill step writes them from stats/current.json (C963).

Ruling (T9, 2026-11-09 08:29): no hand-typed figure in the table or its provenance sentence. The
committed README carries `@@SCAN_*@@` slots, `tools/fill_readme_scan_slots.py` fills them at the
cut, and a slot left over is unshippable.

These tests must pass on the README both before the fill (slots) and after it (the file that
ships), so they run the tool on an in-test template and only assert the shape of the real README.
"""
import importlib.util
import json
import math
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("fill_slots", REPO / "tools" / "fill_readme_scan_slots.py")
fill_slots = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fill_slots)

STATS_PATH = REPO / "stats" / "current.json"
STATS = json.loads(STATS_PATH.read_text(encoding="utf-8"))
README = (REPO / "README.md").read_text(encoding="utf-8")

# The four table rows and the provenance sentence as the README writes them, with their slots.
TEMPLATE = """\
| Scan latency, short input (@@SCAN_SHORT_CHARS@@ chars) | ~@@SCAN_SHORT_MS@@ ms |
| Scan latency, typical attack string (median of @@SCAN_ATTACK_N@@) | ~@@SCAN_ATTACK_MS@@ ms |
| Scan latency, real README (median of @@SCAN_DOC_N@@, median size @@SCAN_DOC_BYTES@@ bytes) | ~@@SCAN_DOC_MS@@ ms |
| Sustained throughput | ~@@SCAN_KBPS@@ KB/sec, single-threaded |
Reproduce with `python3 tools/gen_perf_stats.py`. @@SCAN_PROVENANCE@@ Your hardware will differ.
"""


def _expected_lines(stats):
    s = stats["scan_speed"]
    return [
        f"short input ({s['quickstart_input_chars']} chars) | ~{s['quickstart_median_ms']:.1f} ms |",
        f"(median of {s['attack_corpus_n']}) | ~{s['attack_median_ms']:.1f} ms |",
        f"(median of {s['document_corpus_n']}, median size {s['document_median_bytes']:,} bytes) "
        f"| ~{s['document_median_ms']:.0f} ms |",
        f"| ~{s['throughput_kb_per_sec']:.0f} KB/sec, single-threaded |",
        stats["scan_speed_provenance"].strip(),
    ]


def test_template_carries_exactly_the_slots_the_tool_fills():
    assert set(re.findall(r"@@SCAN_[A-Z_]+@@", TEMPLATE)) == set(fill_slots.SLOTS)


def test_the_committed_readme_is_slotted_or_matches_the_stats():
    """Before the cut: only known slots. After the fill: no slot, and the table says what stats says."""
    found = set(re.findall(r"@@SCAN_[A-Z_]+@@", README))
    if found:
        assert found == set(fill_slots.SLOTS), "an unknown or missing @@SCAN_ slot in the README"
    else:
        for line in _expected_lines(STATS):
            assert line in README, line


def test_fill_writes_the_stats_values_and_leaves_no_slot():
    out = fill_slots.fill(TEMPLATE, STATS)
    assert "@@" not in out
    for line in _expected_lines(STATS):
        assert line in out, line


def test_fill_changes_only_the_slot_lines():
    out = fill_slots.fill(TEMPLATE, STATS)
    before, after = TEMPLATE.splitlines(), out.splitlines()
    assert len(before) == len(after)
    assert all("@@SCAN_" in a for a, b in zip(before, after) if a != b)


def test_fill_refuses_a_missing_slot_a_missing_key_a_bad_value_and_a_leftover():
    with pytest.raises(ValueError, match="not in the README"):
        fill_slots.fill(TEMPLATE.replace("@@SCAN_KBPS@@", "54"), STATS)
    broken = json.loads(json.dumps(STATS))
    del broken["scan_speed"]["attack_median_ms"]
    with pytest.raises(ValueError, match="stats has no"):
        fill_slots.fill(TEMPLATE, broken)
    for bad in (math.nan, math.inf, -1.0, 0, None, "fast", True):
        broken = json.loads(json.dumps(STATS))
        broken["scan_speed"]["document_median_ms"] = bad
        with pytest.raises(ValueError, match="not usable"):
            fill_slots.fill(TEMPLATE, broken)
    empty = json.loads(json.dumps(STATS))
    empty["scan_speed_provenance"] = "  "
    with pytest.raises(ValueError, match="not usable"):
        fill_slots.fill(TEMPLATE, empty)
    with pytest.raises(ValueError, match="left after filling"):
        fill_slots.fill(TEMPLATE + "\n@@SCAN_EXTRA@@\n", STATS)


def test_cli_fills_a_copy_refuses_without_writing_and_check_flags_a_left_slot(tmp_path, capsys):
    readme = tmp_path / "README.md"
    readme.write_text(TEMPLATE, encoding="utf-8")
    assert fill_slots.main(["--readme", str(readme), "--check"]) == 1
    assert fill_slots.main(["--readme", str(readme), "--stats", str(STATS_PATH)]) == 0
    assert readme.read_text(encoding="utf-8") == fill_slots.fill(TEMPLATE, STATS)
    assert fill_slots.main(["--readme", str(readme), "--check"]) == 0
    # a second run finds no slot: it says so rather than silently passing
    assert fill_slots.main(["--readme", str(readme), "--stats", str(STATS_PATH)]) == 1
    assert "refused" in capsys.readouterr().err
    # a stats file with a null value refuses cleanly (rc 1, README untouched)
    bad = tmp_path / "bad.json"
    broken = json.loads(json.dumps(STATS))
    broken["scan_speed"]["attack_median_ms"] = None
    bad.write_text(json.dumps(broken), encoding="utf-8")
    readme.write_text(TEMPLATE, encoding="utf-8")
    assert fill_slots.main(["--readme", str(readme), "--stats", str(bad)]) == 1
    assert readme.read_text(encoding="utf-8") == TEMPLATE
