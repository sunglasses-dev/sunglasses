"""scripts/sync-stats.py must carry the language count it prints.

7447e5b (#147) made sync_readme read stats["dedicated_pattern_languages"] but
get_real_stats() never produced that key, so every run of the script died with
a KeyError before it touched a file. The value comes from the generator
(tools/gen_language_stats.py), the same source stats/current.json records.
"""
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_get_real_stats_carries_the_generated_language_count():
    sync = _load(ROOT / "scripts" / "sync-stats.py", "sync_stats_under_test")
    gen = _load(ROOT / "tools" / "gen_language_stats.py", "gen_language_stats_under_test")
    stats = sync.get_real_stats()
    assert stats["dedicated_pattern_languages"] == gen.measure()["dedicated_pattern_languages"]
    recorded = json.loads((ROOT / "stats" / "current.json").read_text())
    assert stats["dedicated_pattern_languages"] == recorded["dedicated_pattern_languages"]


def test_sync_readme_runs_on_real_stats(tmp_path, monkeypatch):
    sync = _load(ROOT / "scripts" / "sync-stats.py", "sync_stats_under_test_readme")
    stats = sync.get_real_stats()
    (tmp_path / "README.md").write_text(
        "Text scanning: 1 patterns, 1 keywords, 99 languages, 1 attack categories\n"
    )
    monkeypatch.setattr(sync, "REPO_ROOT", tmp_path)
    sync.sync_readme(stats)
    assert f'{stats["dedicated_pattern_languages"]} languages' in (tmp_path / "README.md").read_text()
