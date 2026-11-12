"""scan_speed_provenance: the sentence under the README speed table is written by the generator.

It used to be typed by hand ("Measured ... on the published 0.6.16 wheel ... 3 quiet runs"), so a
re-measure left the README printing figures from one run next to a sentence about another. These tests
pin that the generator writes the sentence from its own run, that the figures it keeps are one whole
pass (the middle one), and that the README prints exactly that sentence. They assert shape, never a
duration.
"""
import importlib.util
import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("gen_perf_stats", ROOT / "tools" / "gen_perf_stats.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

_fill_spec = importlib.util.spec_from_file_location(
    "fill_readme_scan_slots", ROOT / "tools" / "fill_readme_scan_slots.py")
fill_mod = importlib.util.module_from_spec(_fill_spec)
_fill_spec.loader.exec_module(fill_mod)

MACHINE = {"machine": "arm64", "python": "3.14.7"}


def _scan(attack_ms, tag):
    """A fake pass; `tag` rides in quickstart so a test can tell which pass was kept."""
    return {
        "scan_speed": {
            "quickstart_median_ms": tag, "quickstart_input_chars": 18,
            "attack_median_ms": attack_ms, "attack_corpus_n": 38,
            "document_median_ms": 70.0, "document_corpus_n": 77,
            "document_median_bytes": 8246, "throughput_kb_per_sec": 100.0,
        },
        "scan_speed_display": f"pass {tag}",
        "scan_speed_display_short": f"pass {tag}",
        "scan_speed_display_long": f"pass {tag}",
    }


def test_middle_run_is_the_middle_attack_median_whole():
    runs = [_scan(3.0, 1), _scan(1.0, 2), _scan(2.0, 3)]
    kept = gen.middle_run(runs)
    assert kept["scan_speed"]["attack_median_ms"] == 2.0
    assert kept["scan_speed_display"] == "pass 3"          # the whole pass, display included


def test_middle_run_tie_goes_to_the_earlier_run():
    runs = [_scan(2.0, 1), _scan(2.0, 2), _scan(2.0, 3)]
    assert gen.middle_run(runs)["scan_speed"]["quickstart_median_ms"] == 2
    assert gen.middle_run([_scan(5.0, 9)])["scan_speed"]["quickstart_median_ms"] == 9


def test_provenance_carries_date_version_machine_runs_and_corpus():
    text = gen.build_provenance("2026-11-12", "0.6.22", MACHINE, 3, 77)
    assert text == (
        "Measured 2026-11-12 on the sunglasses 0.6.22 source tree (arm64, Python 3.14.7). "
        "Three runs over a corpus of 77 documents. "
        "The run with the middle attack string time is the one shown.")
    assert "wheel" not in text
    assert text.endswith(".")
    # README copy rules: no dash or colon in the prose around the date and the version.
    prose = text.replace("2026-11-12", "").replace("0.6.22", "")
    assert "-" not in prose and ":" not in prose and "\u2014" not in prose and "\u2013" not in prose
    one = gen.build_provenance("2026-11-12", "0.6.22", MACHINE, 1, 77)
    assert one.endswith("One run over a corpus of 77 documents.")
    assert "middle" not in one


def _patched_measure(monkeypatch, runs):
    passes = iter([_scan(a, i + 1) for i, a in enumerate((3.0, 1.0, 2.0)[:runs])])
    monkeypatch.setattr(gen, "_measure_scan_once", lambda: next(passes))
    monkeypatch.setattr(gen, "measure_hook", lambda: {"stub": True})
    return gen.measure(runs=runs)


def test_measure_writes_provenance_from_its_own_run(monkeypatch):
    got = _patched_measure(monkeypatch, 3)
    prov = got["scan_speed_provenance"]
    assert got["scan_speed_generated_at"][:10] in prov            # its own date
    assert gen.SUNGLASSES_VERSION in prov                          # its own version
    assert "Three runs" in prov and "77 documents" in prov              # its own run count and corpus
    assert got["scan_speed"]["attack_median_ms"] == 2.0            # the middle pass was kept
    assert got["hook_speed"] == {"stub": True}


def test_measure_with_one_run_says_one_run(monkeypatch):
    got = _patched_measure(monkeypatch, 1)
    assert "One run" in got["scan_speed_provenance"]


def test_measure_refuses_zero_runs():
    with pytest.raises(ValueError):
        gen.measure(runs=0)


def test_measure_reports_every_pass(monkeypatch):
    seen = []
    passes = iter([_scan(a, i + 1) for i, a in enumerate((3.0, 1.0, 2.0))])
    monkeypatch.setattr(gen, "_measure_scan_once", lambda: next(passes))
    monkeypatch.setattr(gen, "measure_hook", lambda: {})
    gen.measure(runs=3, report=lambda n, load, scan: seen.append((n, scan["attack_median_ms"])))
    assert seen == [(1, 3.0), (2, 1.0), (3, 2.0)]


def test_full_write_replaces_a_stale_hand_typed_provenance(tmp_path, monkeypatch):
    path = tmp_path / "current.json"
    path.write_text(json.dumps({
        "scan_speed_provenance": "Measured 2026-10-30 on the published sunglasses 0.6.16 wheel, 3 quiet runs.",
        "released": "2026-11-08", "version": "0.6.20",
    }), encoding="utf-8")
    measured = _patched_measure(monkeypatch, 3)
    gen.write_full(str(path), measured)
    after = json.loads(path.read_text(encoding="utf-8"))
    assert "0.6.16" not in after["scan_speed_provenance"]
    assert after["scan_speed_provenance"] == measured["scan_speed_provenance"]
    assert after["released"] == "2026-11-08" and after["version"] == "0.6.20"   # untouched keys stay


def test_readme_prints_the_sentence_the_generator_wrote(tmp_path, monkeypatch):
    """The filler writes the run's own provenance, verbatim, into the line the README keeps for it.

    Run on an in-test template, not on README.md: the committed README carries slots before a cut and
    the filled text after it, and this test must hold on both.
    """
    stats = json.loads((ROOT / "stats" / "current.json").read_text(encoding="utf-8"))
    measured = _patched_measure(monkeypatch, 3)
    stats["scan_speed_provenance"] = measured["scan_speed_provenance"]
    line = "Reproduce with `python3 tools/gen_perf_stats.py`. @@SCAN_PROVENANCE@@ Your hardware will differ."
    other = [s for s in fill_mod.SLOTS if s != "@@SCAN_PROVENANCE@@"]
    template = line + "\n" + "\n".join(other) + "\n"
    filled = fill_mod.fill(template, stats)
    assert f"Reproduce with `python3 tools/gen_perf_stats.py`. {measured['scan_speed_provenance']} Your hardware will differ." in filled
    assert not re.search(r"@@[A-Z]", filled)
    # the README keeps that exact line shape, with the slot before a cut or the sentence after it
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"Reproduce with `python3 tools/gen_perf_stats\.py`\. .+ Your hardware will differ\.", readme)
