"""scripts/sync-stats.py rewrites a site page count only when it equals the previous total.

The generic "N patterns" rule used to match any 3-6 character number whenever no previous value
was passed in, and nothing ever passed one in. Run by hand on Oct 16 2026 it rewrote 13 per-chapter
labels ("Chapter 01 · 156 patterns" became "1569 patterns") and dropped the comma from "6,675
keywords". These tests pin the rule: the total moves, in its own comma style; every other count
survives and is listed; with no known previous total nothing is rewritten.
"""
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]

CHAPTER_LABELS = [("01", 156), ("02", 181), ("03", 161), ("04", 140), ("05", 125), ("06", 114),
                  ("07", 133), ("08", 198), ("09", 177), ("10", 279), ("11", 102), ("12", 145),
                  ("13", 119)]


def _sync():
    spec = importlib.util.spec_from_file_location("sync_stats_prev_total_under_test",
                                                  ROOT / "scripts" / "sync-stats.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _site(tmp_path, monkeypatch, recorded=None):
    sync = _sync()
    (tmp_path / "stats").mkdir()
    if recorded is not None:
        (tmp_path / "stats" / "current.json").write_text(json.dumps(recorded))
    monkeypatch.setattr(sync, "WEBSITE_ROOT", tmp_path)
    return sync


def _chapters():
    return "\n".join(f'<div class="cl-label">Chapter {n} &middot; {c} patterns</div>'
                     for n, c in CHAPTER_LABELS)


def _page(extra="", worded_as_now=False):
    """A page as the site carries it: the old wording, or (worded_as_now) the wording this sync writes."""
    said = ("1,569 patterns that carry a matcher across 117 listed categories" if worded_as_now
            else "1,569 detection patterns across 117 attack categories")
    return (f"<p>Sunglasses has {said} and "
            f"6,675 keywords.</p>\n{_chapters()}\n{extra}\n")


STATS_NEW = {"patterns": 1570, "keywords": 6700, "categories": 117}
RECORDED_OLD = {"patterns": 1569, "keywords": 6675, "categories": 117}


def test_the_total_moves_in_its_own_comma_style_and_every_other_count_survives(tmp_path, monkeypatch, capsys):
    sync = _site(tmp_path, monkeypatch, RECORDED_OLD)
    page = tmp_path / "compare.html"
    page.write_text(_page())
    assert sync.sync_website_pages(dict(STATS_NEW)) is True
    text = page.read_text()
    assert "1,570 patterns that carry a matcher across 117 listed categories and 6,700 keywords" in text
    assert "detection patterns" not in text and "attack categories" not in text
    for n, c in CHAPTER_LABELS:
        assert f"Chapter {n} &middot; {c} patterns" in text, (n, c)
    assert "1569" not in text
    out = capsys.readouterr().out
    assert "SKIPPED 13 count(s)" in out
    for _, c in CHAPTER_LABELS:
        assert f"compare.html: {c} patterns" in out, c


def test_a_run_with_nothing_to_move_leaves_the_page_byte_identical(tmp_path, monkeypatch):
    """The Oct 16 run dropped the comma of an unchanged 6,675 and rewrote the labels; this is that run."""
    sync = _site(tmp_path, monkeypatch, RECORDED_OLD)
    page = tmp_path / "faq.html"
    page.write_text(_page(worded_as_now=True))
    before = page.read_bytes()
    assert sync.sync_website_pages(dict(RECORDED_OLD)) is False
    assert page.read_bytes() == before


def test_a_plain_number_stays_plain_and_a_stale_total_that_is_not_the_previous_one_is_listed_not_rewritten(
        tmp_path, monkeypatch, capsys):
    sync = _site(tmp_path, monkeypatch, RECORDED_OLD)
    page = tmp_path / "index-like.html"
    page.write_text("<p>1569 patterns today.</p><p>An older note says 1,046 detection patterns.</p>")
    sync.sync_website_pages(dict(STATS_NEW))
    text = page.read_text()
    assert "1570 patterns that carry a matcher today." in text
    assert "1,046 detection patterns" in text
    assert "index-like.html: 1,046 detection patterns" in capsys.readouterr().out


def test_an_explicit_previous_value_wins_over_the_recorded_file(tmp_path, monkeypatch):
    sync = _site(tmp_path, monkeypatch, RECORDED_OLD)
    page = tmp_path / "how.html"
    page.write_text("<p>1,046 detection patterns, and 1,569 detection patterns.</p>")
    sync.sync_website_pages({**STATS_NEW, "_prev_patterns": "1,046"})
    assert page.read_text() == "<p>1,570 patterns that carry a matcher, and 1,569 detection patterns.</p>"


def test_with_no_known_previous_total_nothing_is_rewritten_and_the_run_says_so(tmp_path, monkeypatch, capsys):
    sync = _site(tmp_path, monkeypatch, recorded=None)
    page = tmp_path / "faq.html"
    page.write_text(_page())
    before = page.read_bytes()
    assert sync.sync_website_pages(dict(STATS_NEW)) is False
    assert page.read_bytes() == before
    assert "no previous patterns total known" in capsys.readouterr().out


def test_dated_pages_and_historical_wording_are_still_left_alone(tmp_path, monkeypatch):
    sync = _site(tmp_path, monkeypatch, RECORDED_OLD)
    (tmp_path / "blog").mkdir()
    blog = tmp_path / "blog" / "post.html"
    blog.write_text("<p>1,569 detection patterns.</p>")
    page = tmp_path / "about.html"
    page.write_text("<p>v0.6.9 shipped with 1,569 detection patterns.</p>")
    sync.sync_website_pages(dict(STATS_NEW))
    assert blog.read_text() == "<p>1,569 detection patterns.</p>"
    assert page.read_text() == "<p>v0.6.9 shipped with 1,569 detection patterns.</p>"


def test_a_page_with_the_old_wording_and_the_current_total_gets_the_new_wording(tmp_path, monkeypatch):
    """The labels are migrated with the number: the total already being right does not keep
    "detection patterns" / "attack categories" on the page."""
    sync = _site(tmp_path, monkeypatch, RECORDED_OLD)
    page = tmp_path / "faq.html"
    page.write_text(_page())
    assert sync.sync_website_pages(dict(RECORDED_OLD)) is True
    assert page.read_text() == _page(worded_as_now=True)
    assert sync.sync_website_pages(dict(RECORDED_OLD)) is False  # and a second run changes nothing


def test_threat_categories_is_a_different_count_and_keeps_its_words(tmp_path, monkeypatch):
    sync = _site(tmp_path, monkeypatch, RECORDED_OLD)
    page = tmp_path / "faq.html"
    page.write_text("<p>117 threat categories, 117 categories, 117 listed categories.</p>")
    sync.sync_website_pages(dict(RECORDED_OLD))
    assert page.read_text() == "<p>117 threat categories, 117 listed categories, 117 listed categories.</p>"


def test_the_home_page_json_ld_name_moves_with_the_number(tmp_path, monkeypatch):
    """The old name said "detectionPatterns"; the number is the patterns that carry a matcher."""
    sync = _site(tmp_path, monkeypatch, RECORDED_OLD)
    ld = ('<script type="application/ld+json">{"additionalProperty": ['
          '{"@type": "PropertyValue", "name": "%s", "value": %s}]}</script>')
    for old_name in ("detectionPatterns", "patternsWithMatcher"):
        (tmp_path / "index.html").write_text(ld % (old_name, 1569))
        sync.sync_website_index({**STATS_NEW, "version": "0.6.17", "date": "2026-11-01"})
        assert (tmp_path / "index.html").read_text() == ld % ("patternsWithMatcher", 1570), old_name
