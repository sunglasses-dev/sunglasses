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


TEXT_LINE = "- \u2705 Text scanning: {} patterns that carry a matcher ({} listed), {} indexed keywords ({} declared), {} listed categories (English-first, see [Language coverage](#language-coverage-measured))"


def _expected_line(stats):
    return TEXT_LINE.format(f'{stats["patterns"]:,}', f'{stats["listed_patterns"]:,}', f'{stats["keywords"]:,}',
                            f'{stats["keywords_declared"]:,}', f'{stats["categories"]:,}')


def test_sync_readme_rewrites_the_text_scanning_line(tmp_path, monkeypatch):
    """The line must be REWRITTEN, counted, not merely survive the run."""
    sync = _load(ROOT / "scripts" / "sync-stats.py", "sync_stats_under_test_readme")
    stats = sync.get_real_stats()
    stale = TEXT_LINE.format("1", "2", "3", "4", "5")
    (tmp_path / "README.md").write_text(f"x\n{stale}\ny\n")
    monkeypatch.setattr(sync, "REPO_ROOT", tmp_path)
    assert sync.sync_readme(stats) is True
    lines = (tmp_path / "README.md").read_text().splitlines()
    assert lines.count(_expected_line(stats)) == 1
    assert stale not in lines


def test_sync_readme_text_scanning_line_matches_the_real_readme(tmp_path, monkeypatch):
    """Against the real README the pattern must hit exactly one line, and a current
    README must come out byte-identical (the index count first, the declared count in brackets)."""
    sync = _load(ROOT / "scripts" / "sync-stats.py", "sync_stats_under_test_real")
    stats = sync.get_real_stats()
    real = (ROOT / "README.md").read_text()
    assert sum(1 for l in real.splitlines() if "Text scanning:" in l) == 1
    assert real.splitlines().count(_expected_line(stats)) == 1, "README line is not current"
    (tmp_path / "README.md").write_text(real)
    monkeypatch.setattr(sync, "REPO_ROOT", tmp_path)
    assert sync.sync_readme(stats) is False
    assert (tmp_path / "README.md").read_text() == real


KEYWORDS_ROW = ("| Keywords | {} unique declared ({} entries across all patterns); the pre-screen "
                "index holds {} ({} generic keywords are deliberately excluded from it). "
                "`engine.info()` reports all three (`keywords_declared`, `keyword_entries`, `keywords`) |")


def _expected_table(stats):
    d, e, i = stats["keywords_declared"], stats["keyword_entries"], stats["keywords"]
    return [f'| Patterns | {stats["patterns"]:,} carry a matcher ({stats["listed_patterns"]:,} listed) |',
            KEYWORDS_ROW.format(f"{d:,}", f"{e:,}", f"{i:,}", f"{d - i:,}"),
            f'| Attack categories | {stats["categories"]:,} listed |']


def test_sync_readme_rewrites_every_stats_table_row(tmp_path, monkeypatch):
    """Each row is REWRITTEN, counted once. The declared count goes in the declared
    slot and the index count only in the index slot, never the other way round."""
    sync = _load(ROOT / "scripts" / "sync-stats.py", "sync_stats_under_test_table")
    stats = sync.get_real_stats()
    stale = ["| Patterns | 1 |", KEYWORDS_ROW.format("2", "3", "4", "5"), "| Attack categories | 6 |"]
    (tmp_path / "README.md").write_text("\n".join(["x", *stale, "y"]) + "\n")
    monkeypatch.setattr(sync, "REPO_ROOT", tmp_path)
    assert sync.sync_readme(stats) is True
    lines = (tmp_path / "README.md").read_text().splitlines()
    for want in _expected_table(stats):
        assert lines.count(want) == 1, want
    assert not set(stale) & set(lines)


def test_real_readme_stats_table_is_current_and_each_row_is_hit_once():
    sync = _load(ROOT / "scripts" / "sync-stats.py", "sync_stats_under_test_table_real")
    lines = (ROOT / "README.md").read_text().splitlines()
    for want in _expected_table(sync.get_real_stats()):
        assert lines.count(want) == 1, f"README table row not current: {want[:60]}"


OPENING = ("A local scanner checks text with {} patterns that carry a matcher ({} are listed) "
           "across {} listed categories and reports findings.")
UNDER_TABLE = "The ruleset lists {}; the other {} carry neither. Carrying a matcher is not proof."
ATTACK_DB = ("**{} patterns across {} attack categories.** These are the listed rules: "
             "{} of them carry a regex or keyword matcher and {} carry none.")


def test_sync_readme_keeps_the_split_sentences_in_step_with_the_counts(tmp_path, monkeypatch):
    """The opening line, the sentence under the table and attack-db/README.md state the same split
    as the table; a moved count must move them too, not leave 1,512 / 71 behind."""
    sync = _load(ROOT / "scripts" / "sync-stats.py", "sync_stats_under_test_split")
    stats = {**sync.get_real_stats(), "patterns": 1513, "listed_patterns": 1590, "categories": 118}
    (tmp_path / "attack-db").mkdir()
    (tmp_path / "README.md").write_text(
        "\n".join([OPENING.format("1,512", "1,583", "117"), UNDER_TABLE.format("1,583", "71")]) + "\n")
    (tmp_path / "attack-db" / "README.md").write_text(ATTACK_DB.format("1,583", "117", "1,512", "71") + "\n")
    monkeypatch.setattr(sync, "REPO_ROOT", tmp_path)
    assert sync.sync_readme(stats) is True
    assert (tmp_path / "README.md").read_text().splitlines() == [
        OPENING.format("1,513", "1,590", "118"), UNDER_TABLE.format("1,590", "77")]
    assert (tmp_path / "attack-db" / "README.md").read_text() == ATTACK_DB.format("1,590", "118", "1,513", "77") + "\n"
    assert sync.sync_readme(stats) is False  # a second run has nothing left to move


def test_sync_readme_leaves_the_real_split_sentences_alone_and_hits_each_once(tmp_path, monkeypatch):
    sync = _load(ROOT / "scripts" / "sync-stats.py", "sync_stats_under_test_split_real")
    stats = sync.get_real_stats()
    (tmp_path / "attack-db").mkdir()
    real = (ROOT / "README.md").read_text()
    real_db = (ROOT / "attack-db" / "README.md").read_text()
    assert real.count("patterns that carry a matcher (") >= 2 and real.count("carry neither.") == 1
    (tmp_path / "README.md").write_text(real)
    (tmp_path / "attack-db" / "README.md").write_text(real_db)
    monkeypatch.setattr(sync, "REPO_ROOT", tmp_path)
    assert sync.sync_readme(stats) is False
    assert (tmp_path / "README.md").read_text() == real
    assert (tmp_path / "attack-db" / "README.md").read_text() == real_db
