"""The public scan-speed phrases print the attack figure with one decimal, like the README table.

The README table prints the attack median as `~3.8 ms`, filled from `scan_speed.attack_median_ms`.
The display strings in `stats/current.json` were built from the same key with no decimal, so the
site read `~4ms` beside the README's `~3.8ms`. These tests pin the formatter and tie the
committed strings to it, from the stored measurements and without a timing run.
"""
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATS = ROOT / "stats" / "current.json"

_spec = importlib.util.spec_from_file_location("gen_perf_stats", ROOT / "tools" / "gen_perf_stats.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def test_short_phrase_prints_the_attack_median_with_one_decimal():
    assert gen._display(1.538, 3.84) == "~1.5ms short input, ~3.8ms typical attack string"


def test_long_phrase_prints_the_attack_median_with_one_decimal():
    text = gen._display_long(1.538, 3.84, 53.9)
    assert "~3.8ms on a typical attack string" in text
    assert "~54 KB/sec sustained" in text


def test_a_whole_number_median_keeps_its_decimal():
    assert "~4.0ms typical attack string" in gen._display(1.5, 4.0)


def test_committed_display_strings_are_the_formatters_output_for_the_stored_figures():
    stats = json.loads(STATS.read_text(encoding="utf-8"))
    s = stats["scan_speed"]
    short = gen._display(s["quickstart_median_ms"], s["attack_median_ms"])
    long_ = gen._display_long(s["quickstart_median_ms"], s["attack_median_ms"], s["throughput_kb_per_sec"])
    assert stats["scan_speed_display"] == short
    assert stats["scan_speed_display_short"] == short
    assert stats["scan_speed_display_long"] == long_
