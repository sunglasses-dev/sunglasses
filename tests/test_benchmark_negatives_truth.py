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
