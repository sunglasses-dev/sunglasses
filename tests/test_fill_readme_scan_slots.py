"""The README's measured figures are slots; the fill step writes them from stats/current.json (C963, C976).

Ruling (T9, 2026-11-09 08:29): no hand-typed figure in the scan table, its provenance sentence, the
WARN-lane bullet or the Cost line. The committed README carries `@@NAME@@` slots,
`tools/fill_readme_scan_slots.py` fills them at the cut, and a slot left over is unshippable.

These tests must pass on the README both before the fill (slots) and after it (the file that
ships), so they run the tool on in-test templates and in-test stats and only assert the shape of
the real README. The `hook_speed` block is built in the test: the committed stats file only gets
it from the hook-speed generator at the cut.
"""
import copy
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
FILE_STATS = json.loads(STATS_PATH.read_text(encoding="utf-8"))
README = (REPO / "README.md").read_text(encoding="utf-8")

HOOK = {
    "hook_lane_off_min_ms": 31.8,
    "hook_lane_off_median_ms": 32.9,
    "hook_lane_on_min_ms": 100.5,
    "hook_lane_on_median_ms": 103.7,
    "python_start_min_ms": 22.8,
    "python_start_median_ms": 24.3,
    "repeats": 15,
    "version": "0.6.20",
    "measured_on": {"machine": "arm64", "system": "Darwin 27.0.0", "python": "3.14.7"},
    "measured_at": "2026-11-09T07:44:36-08:00",
}
# The scan numbers come from the committed file when it has them; the hook block is always the test's own.
STATS = copy.deepcopy(FILE_STATS)
STATS["hook_speed"] = copy.deepcopy(HOOK)

# The scan rows and the provenance sentence as the README writes them, with their slots.
SCAN_TEMPLATE = """\
| Scan latency, short input (@@SCAN_SHORT_CHARS@@ chars) | ~@@SCAN_SHORT_MS@@ ms |
| Scan latency, typical attack string (median of @@SCAN_ATTACK_N@@) | ~@@SCAN_ATTACK_MS@@ ms |
| Scan latency, real README (median of @@SCAN_DOC_N@@, median size @@SCAN_DOC_BYTES@@ bytes) | ~@@SCAN_DOC_MS@@ ms |
| Sustained throughput | ~@@SCAN_KBPS@@ KB/sec, single threaded |
Reproduce with `python3 tools/gen_perf_stats.py`. @@SCAN_PROVENANCE@@ Your hardware will differ.
"""
# The WARN-lane bullet and the Cost line, copied from the README (a test below keeps them equal).
HOOK_TEMPLATE = """\
  taste: a few ordinary tool calls escalate (a plain `curl -s pypi.org` has read
  as a dangerous shell command), and the lane adds time to every call: about
  @@LANE_ON_MS@@ ms per tool call with it on against @@LANE_OFF_MS@@ ms with it
  off, measured on @@VERSION@@, @@DATE@@ (ledger entry). Enable with
About @@LANE_OFF_MS@@ ms per tool call with the pattern lane off (the default) and about
@@LANE_ON_MS@@ ms with it on (the installed hook command, whole process, min of @@REPEATS@@ runs,
a benign Bash call, measured on @@VERSION@@, @@DATE@@, on @@MACHINE_CLASS@@; bare Python
startup is @@PY_START_MS@@ ms of that). Zero network calls (nothing about your work leaves the
"""
HOOK_EXPECTED = """\
  taste: a few ordinary tool calls escalate (a plain `curl -s pypi.org` has read
  as a dangerous shell command), and the lane adds time to every call: about
  100 ms per tool call with it on against 32 ms with it
  off, measured on 0.6.20, 2026-11-09 (ledger entry). Enable with
About 32 ms per tool call with the pattern lane off (the default) and about
100 ms with it on (the installed hook command, whole process, min of 15 runs,
a benign Bash call, measured on 0.6.20, 2026-11-09, on an Apple silicon Mac (arm64, macOS); bare Python
startup is 23 ms of that). Zero network calls (nothing about your work leaves the
"""
TEMPLATE = SCAN_TEMPLATE + HOOK_TEMPLATE
HOOK_SLOTS = {s for s, v in fill_slots.SLOTS.items() if v[0][0] == "hook_speed"}


def _expected_scan_lines(stats):
    s = stats["scan_speed"]
    return [
        f"short input ({s['quickstart_input_chars']} chars) | ~{s['quickstart_median_ms']:.1f} ms |",
        f"(median of {s['attack_corpus_n']}) | ~{s['attack_median_ms']:.1f} ms |",
        f"(median of {s['document_corpus_n']}, median size {s['document_median_bytes']:,} bytes) "
        f"| ~{s['document_median_ms']:.0f} ms |",
        f"| ~{s['throughput_kb_per_sec']:.0f} KB/sec, single threaded |",
        stats["scan_speed_provenance"].strip(),
    ]


def _slots_in(text):
    return set(re.findall(r"@@[A-Z][A-Z_]*@@", text))


def _with(stats, path, value):
    out = copy.deepcopy(stats)
    node = out
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return out


def test_template_carries_exactly_the_slots_the_tool_fills():
    assert _slots_in(TEMPLATE) == set(fill_slots.SLOTS)
    assert HOOK_SLOTS == {
        "@@LANE_ON_MS@@", "@@LANE_OFF_MS@@", "@@PY_START_MS@@", "@@REPEATS@@",
        "@@VERSION@@", "@@DATE@@", "@@MACHINE_CLASS@@",
    }


def test_the_committed_readme_is_slotted_or_matches_the_stats():
    """Before the cut: only known slots, and the hook lines are the template's. After the fill: no slot."""
    found = _slots_in(README)
    if found:
        assert found == set(fill_slots.SLOTS), "an unknown or missing @@ slot in the README"
        for line in HOOK_TEMPLATE.splitlines():
            assert line in README, line
    else:
        assert "hook_speed" in FILE_STATS, "a filled README needs the stats it was filled from"
        for line in _expected_scan_lines(FILE_STATS):
            assert line in README, line
        assert re.search(r"about\s+\d+\s+ms per tool call with it on against \d+ ms", README)


def test_fill_writes_the_stats_values_and_leaves_no_slot():
    out = fill_slots.fill(TEMPLATE, STATS)
    assert "@@" not in out
    for line in _expected_scan_lines(STATS):
        assert line in out, line


def test_fill_output_is_byte_exact_for_the_hook_lines():
    out = fill_slots.fill(TEMPLATE, STATS)
    assert out.endswith(HOOK_EXPECTED)
    assert out.startswith(fill_slots.fill(SCAN_TEMPLATE + HOOK_TEMPLATE, STATS)[: len(out) - len(HOOK_EXPECTED)])
    # 100.5 writes as 100 and 31.8 as 32: whole milliseconds, the same rule the scan table uses
    assert "100 ms per tool call with it on against 32 ms" in out


def test_fill_changes_only_the_slot_lines():
    out = fill_slots.fill(TEMPLATE, STATS)
    before, after = TEMPLATE.splitlines(), out.splitlines()
    assert len(before) == len(after)
    assert all("@@" in a for a, b in zip(before, after) if a != b)


def test_fill_refuses_a_missing_slot_a_missing_key_a_bad_value_and_a_leftover():
    for slot in fill_slots.SLOTS:
        with pytest.raises(ValueError, match="not in the README"):
            fill_slots.fill(TEMPLATE.replace(slot, "54"), STATS)
    broken = copy.deepcopy(STATS)
    del broken["scan_speed"]["attack_median_ms"]
    with pytest.raises(ValueError, match="stats has no"):
        fill_slots.fill(TEMPLATE, broken)
    for bad in (math.nan, math.inf, -1.0, 0, None, "fast", True):
        with pytest.raises(ValueError, match="not usable"):
            fill_slots.fill(TEMPLATE, _with(STATS, ("scan_speed", "document_median_ms"), bad))
    empty = _with(STATS, ("scan_speed_provenance",), "  ")
    with pytest.raises(ValueError, match="not usable"):
        fill_slots.fill(TEMPLATE, empty)
    with pytest.raises(ValueError, match="left after filling"):
        fill_slots.fill(TEMPLATE + "\n@@SCAN_EXTRA@@\n", STATS)


def test_fill_refuses_every_hook_slot_the_same_way():
    # the whole block missing, or one key missing: refused, never a partial fill
    no_block = copy.deepcopy(STATS)
    del no_block["hook_speed"]
    with pytest.raises(ValueError, match="stats has no hook_speed"):
        fill_slots.fill(TEMPLATE, no_block)
    for key in ("hook_lane_on_min_ms", "hook_lane_off_min_ms", "python_start_min_ms", "repeats",
                "version", "measured_at", "measured_on"):
        gone = copy.deepcopy(STATS)
        del gone["hook_speed"][key]
        with pytest.raises(ValueError, match="stats has no"):
            fill_slots.fill(TEMPLATE, gone)
    # every number: NaN, inf, negative, zero, null, text and a bool are all refused
    for key in ("hook_lane_on_min_ms", "hook_lane_off_min_ms", "python_start_min_ms", "repeats"):
        for bad in (math.nan, math.inf, -1.0, 0, None, "fast", True):
            with pytest.raises(ValueError, match="not usable"):
                fill_slots.fill(TEMPLATE, _with(STATS, ("hook_speed", key), bad))
    for bad in ("", "  ", None, 6, "v0.6.20", "0.6", "0.6.20rc1"):
        with pytest.raises(ValueError, match="not usable"):
            fill_slots.fill(TEMPLATE, _with(STATS, ("hook_speed", "version"), bad))
    for bad in ("", "yesterday", None, 20261109, "09/11/2026", "2026-11"):
        with pytest.raises(ValueError, match="not usable"):
            fill_slots.fill(TEMPLATE, _with(STATS, ("hook_speed", "measured_at"), bad))
    for bad in (None, "arm64", {}, {"machine": "arm64"}, {"system": "Darwin 27.0.0"},
                {"machine": "", "system": "Darwin 27.0.0"}, {"machine": "arm64", "system": "  "},
                {"machine": 1, "system": 2}):
        with pytest.raises(ValueError, match="not usable"):
            fill_slots.fill(TEMPLATE, _with(STATS, ("hook_speed", "measured_on"), bad))
    # an unknown hook slot in the README is a leftover, not a silent skip
    for extra in ("@@HOOK_EXTRA@@", "@@LANE_MEDIAN_MS@@"):
        with pytest.raises(ValueError, match="left after filling"):
            fill_slots.fill(TEMPLATE + f"\n{extra}\n", STATS)


def test_a_failed_fill_does_not_change_the_template_and_a_second_fill_is_identical():
    before = TEMPLATE
    with pytest.raises(ValueError):
        fill_slots.fill(TEMPLATE, _with(STATS, ("hook_speed", "repeats"), 0))
    assert TEMPLATE == before
    assert fill_slots.fill(TEMPLATE, STATS) == fill_slots.fill(TEMPLATE, copy.deepcopy(STATS))


def test_cli_fills_a_copy_refuses_without_writing_and_check_flags_a_left_slot(tmp_path, capsys):
    stats_file = tmp_path / "stats.json"
    stats_file.write_text(json.dumps(STATS), encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text(TEMPLATE, encoding="utf-8")
    assert fill_slots.main(["--readme", str(readme), "--check"]) == 1
    assert fill_slots.main(["--readme", str(readme), "--stats", str(stats_file)]) == 0
    assert readme.read_text(encoding="utf-8") == fill_slots.fill(TEMPLATE, STATS)
    assert fill_slots.main(["--readme", str(readme), "--check"]) == 0
    # a second run finds no slot: it says so rather than silently passing
    assert fill_slots.main(["--readme", str(readme), "--stats", str(stats_file)]) == 1
    assert "refused" in capsys.readouterr().err
    # a stats file with a null value (scan or hook) refuses cleanly (rc 1, README untouched)
    for path in (("scan_speed", "attack_median_ms"), ("hook_speed", "hook_lane_on_min_ms")):
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(_with(STATS, path, None)), encoding="utf-8")
        readme.write_text(TEMPLATE, encoding="utf-8")
        assert fill_slots.main(["--readme", str(readme), "--stats", str(bad)]) == 1
        assert readme.read_text(encoding="utf-8") == TEMPLATE
    # a stats file without hook_speed (the committed one before the cut) refuses too
    old = copy.deepcopy(STATS)
    del old["hook_speed"]
    bad.write_text(json.dumps(old), encoding="utf-8")
    assert fill_slots.main(["--readme", str(readme), "--stats", str(bad)]) == 1
    assert readme.read_text(encoding="utf-8") == TEMPLATE


def test_machine_class_maps_apple_silicon_to_a_phrase_and_prints_any_other_pair_raw():
    apple = fill_slots.fill(TEMPLATE, STATS)
    assert "on an Apple silicon Mac (arm64, macOS); bare Python" in apple
    assert "27.0.0" not in apple  # the kernel build is not a macOS version and stays in the stats file
    for machine, system, phrase in (
        ("x86_64", "Darwin 23.1.0", "on x86_64, Darwin 23.1.0; bare Python"),
        ("arm64", "Linux 6.8.0", "on arm64, Linux 6.8.0; bare Python"),
        ("aarch64", "Darwin 27.0.0", "on aarch64, Darwin 27.0.0; bare Python"),
        ("AMD64", "Windows 11", "on AMD64, Windows 11; bare Python"),
    ):
        stats = _with(STATS, ("hook_speed", "measured_on"), {"machine": machine, "system": system})
        out = fill_slots.fill(TEMPLATE, stats)
        assert phrase in out, (machine, system)
        assert "Apple silicon" not in out


def test_python_start_comes_from_the_same_hook_block_as_the_lane_figures_and_is_never_typed():
    slots = fill_slots.SLOTS
    # lane-off, lane-on and python-start are three keys of ONE hook_speed block, written by one generator run
    assert {slots[s][0][0] for s in ("@@LANE_OFF_MS@@", "@@LANE_ON_MS@@", "@@PY_START_MS@@")} == {"hook_speed"}
    assert slots["@@PY_START_MS@@"][0] == ("hook_speed", "python_start_min_ms")
    assert slots["@@LANE_OFF_MS@@"][0] == ("hook_speed", "hook_lane_off_min_ms")
    # a different start figure changes only that slot's text
    other = _with(STATS, ("hook_speed", "python_start_min_ms"), 19.2)
    assert "startup is 19 ms of that" in fill_slots.fill(TEMPLATE, other)
    # the README never carries a typed figure there: a slot before the cut, the stats value after it
    if _slots_in(README):
        assert not re.search(r"startup is\s+\d", README)  # no typed figure before the cut
    else:
        py = FILE_STATS["hook_speed"]["python_start_min_ms"]
        assert f"startup is {py:.0f} ms of that" in README  # after the cut: the stats value
