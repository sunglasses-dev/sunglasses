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


TEXT_LINE = "- \u2705 Text scanning: {} patterns, {} unique keywords, {} attack categories (English-first \u2014 see [Language coverage](#language-coverage-measured))"


def _expected_line(stats):
    return TEXT_LINE.format(f'{stats["patterns"]:,}', f'{stats["keywords_declared"]:,}',
                            f'{stats["categories"]:,}')


def test_sync_readme_rewrites_the_text_scanning_line(tmp_path, monkeypatch):
    """The line must be REWRITTEN, counted, not merely survive the run."""
    sync = _load(ROOT / "scripts" / "sync-stats.py", "sync_stats_under_test_readme")
    stats = sync.get_real_stats()
    stale = TEXT_LINE.format("1", "2", "3")
    (tmp_path / "README.md").write_text(f"x\n{stale}\ny\n")
    monkeypatch.setattr(sync, "REPO_ROOT", tmp_path)
    assert sync.sync_readme(stats) is True
    lines = (tmp_path / "README.md").read_text().splitlines()
    assert lines.count(_expected_line(stats)) == 1
    assert stale not in lines


def test_sync_readme_text_scanning_line_matches_the_real_readme(tmp_path, monkeypatch):
    """Against the real README the pattern must hit exactly one line, and a current
    README must come out byte-identical (the declared keyword count, not the index's)."""
    sync = _load(ROOT / "scripts" / "sync-stats.py", "sync_stats_under_test_real")
    stats = sync.get_real_stats()
    real = (ROOT / "README.md").read_text()
    assert sum(1 for l in real.splitlines() if "Text scanning:" in l) == 1
    assert real.splitlines().count(_expected_line(stats)) == 1, "README line is not current"
    (tmp_path / "README.md").write_text(real)
    monkeypatch.setattr(sync, "REPO_ROOT", tmp_path)
    assert sync.sync_readme(stats) is False
    assert (tmp_path / "README.md").read_text() == real
