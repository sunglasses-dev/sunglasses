"""stats/current.json benchmark_negatives must equal the benchmark's live corpus.

The README and the site said 76 clean READMEs for three releases after #219
made the corpus 77, because the number was typed and nothing counted it. The
count comes from the benchmark's own loader (tests/benchmark/precision_recall.py
load_negatives), so a corpus change fails here until the truth file follows.
"""
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_benchmark_negatives_matches_the_live_corpus():
    bench = _load(ROOT / "tests" / "benchmark" / "precision_recall.py", "precision_recall_under_test")
    live = len(bench.load_negatives())
    recorded = json.loads((ROOT / "stats" / "current.json").read_text())
    assert recorded.get("benchmark_negatives") == live, (
        f"stats/current.json benchmark_negatives is {recorded.get('benchmark_negatives')!r}, "
        f"the benchmark corpus has {live} READMEs (tests/fp_real_world_corpus/*.md). "
        f"Update the truth file and every page that quotes the count."
    )


def test_benchmark_recall_and_precision_match_a_live_run():
    """The README and the site quoted "64/64 internal recall, 100% recall" from
    April 2026 for five months. The corpus behind it was never in the repo, so
    nobody outside could reproduce it. The published figure is the shipped
    benchmark, so the truth file must equal what the benchmark prints now."""
    bench = _load(ROOT / "tests" / "benchmark" / "precision_recall.py", "precision_recall_recall_truth")
    m = bench.run()["metrics"]
    recorded = json.loads((ROOT / "stats" / "current.json").read_text())
    assert recorded.get("benchmark_positives") == m["positives"]
    assert recorded.get("benchmark_recall") == f'{m["true_positives"]}/{m["positives"]}'
    assert recorded.get("benchmark_recall_pct") == round(m["recall"] * 100, 1)
    assert recorded.get("benchmark_precision_pct") == round(m["precision"] * 100, 1)


def test_the_retired_recall_claim_is_gone_from_the_truth_file_and_the_readme():
    recorded = json.loads((ROOT / "stats" / "current.json").read_text())
    assert "internal_recall" not in recorded and "internal_recall_pct" not in recorded
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "64/64" not in readme
    assert "100% recall" not in readme
    m = _load(ROOT / "tests" / "benchmark" / "precision_recall.py", "precision_recall_readme_truth").run()["metrics"]
    assert f'recall {round(m["recall"] * 100, 1)}% ({m["true_positives"]}/{m["positives"]})' in readme
    assert f'precision {round(m["precision"] * 100, 1)}%' in readme
