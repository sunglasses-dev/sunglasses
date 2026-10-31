#!/usr/bin/env python3
"""
SUNGLASSES Stats Sync — Single source of truth enforcer.

Reads real numbers from patterns.py, updates everywhere:
- README.md (stats table + "What Works Today" section)
- Website index.html (SUNGLASSES_STATS, JSON-LD, meta tags)
- Website blog posts (any hardcoded pattern/keyword/category counts)
- Website faq.html

Run before any push: python3 scripts/sync-stats.py
"""

import re
import sys
import os
from pathlib import Path
from datetime import date

# Find repo root
REPO_ROOT = Path(__file__).parent.parent
WEBSITE_ROOT = Path.home() / "Desktop" / "sunglasses-dev-landing"

def get_real_stats():
    """Extract actual stats from patterns.py — the single source of truth."""
    sys.path.insert(0, str(REPO_ROOT))
    from sunglasses.patterns import PATTERNS

    # Use the engine for accurate counts (deduplicates keywords like the scanner does)
    from sunglasses.engine import SunglassesEngine
    engine = SunglassesEngine()
    info = engine.info()

    patterns = PATTERNS
    total = info["detecting_patterns"]
    categories = set(p["category"] for p in patterns)
    keyword_count = info["keywords"]  # unique keywords from engine
    regex_count = info["regex_patterns"]

    # The typed language count stats/current.json records, from the same generator,
    # never from a literal. (The README's Text scanning line no longer prints it:
    # it points at the measured coverage table instead.)
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    from gen_language_stats import measure
    languages = measure(patterns)["dedicated_pattern_languages"]

    # Get version
    init_file = REPO_ROOT / "sunglasses" / "__init__.py"
    version = "0.0.0"
    for line in init_file.read_text().splitlines():
        if "__version__" in line:
            version = line.split('"')[1]
            break

    return {
        "patterns": total,
        "listed_patterns": info["listed_patterns"],
        "categories": len(categories),
        "keywords": keyword_count,
        # The README states both: the DECLARED count (table row, and in brackets on the
        # Text scanning line) and `keywords`, the smaller pre-screen index. Each goes
        # only in its own slot.
        "keywords_declared": info["keywords_declared"],
        "keyword_entries": info["keyword_entries"],
        "regex": regex_count,
        "dedicated_pattern_languages": languages,
        "version": version,
        "date": date.today().isoformat(),
    }


def update_file(filepath, replacements, label):
    """Apply regex replacements to a file. Returns True if changed."""
    if not filepath.exists():
        print(f"  SKIP {label} — file not found")
        return False

    content = filepath.read_text()
    original = content
    changes = 0

    for pattern, replacement in replacements:
        new_content = re.sub(pattern, replacement, content)
        if new_content != content:
            changes += 1
        content = new_content

    if content != original:
        filepath.write_text(content)
        print(f"  UPDATED {label} ({changes} changes)")
        return True
    else:
        print(f"  OK {label} (already current)")
        return False


def sync_readme(stats):
    """Update README.md stats table and What Works Today section."""
    readme = REPO_ROOT / "README.md"
    replacements = [
        # Stats table. The README writes thousands separators, so a bare \d+ matched
        # nothing and these were silent no-ops. The Keywords row carries four numbers:
        # the DECLARED count leads, the pre-screen index (stats["keywords"]) appears
        # only where the row says "index holds", and the excluded count is their
        # difference, so the row cannot contradict itself after a sync.
        (r'\| Patterns \| [\d,]+ \|', f'| Patterns | {stats["patterns"]:,} |'),
        (r'\| Keywords \| [\d,]+ unique declared \([\d,]+ entries across all patterns\); '
         r'the pre-screen index holds [\d,]+ \([\d,]+ generic keywords',
         f'| Keywords | {stats["keywords_declared"]:,} unique declared '
         f'({stats["keyword_entries"]:,} entries across all patterns); '
         f'the pre-screen index holds {stats["keywords"]:,} ('
         f'{stats["keywords_declared"] - stats["keywords"]:,} generic keywords'),
        (r'\| Attack categories \| [\d,]+ \|', f'| Attack categories | {stats["categories"]:,} |'),
        # What Works Today header
        (r'What Works Today \(v[\d.]+\)', f'What Works Today (v{stats["version"]})'),
        # What Works Today line. It must match the README as written (thousands
        # separators, no language count), or the replacement is a silent no-op, which
        # it was from #147 until this pattern was fixed. It leads with the index count,
        # the number version.json and `sunglasses info` publish, and names the declared
        # count beside it, so the line never reads as a second "keywords" figure.
        (r'Text scanning: [\d,]+ patterns, [\d,]+ indexed keywords \([\d,]+ declared\), [\d,]+ attack categories',
         f'Text scanning: {stats["patterns"]:,} patterns, {stats["keywords"]:,} indexed keywords '
         f'({stats["keywords_declared"]:,} declared), {stats["categories"]:,} attack categories'),
    ]
    return update_file(readme, replacements, "README.md")


def sync_website_index(stats):
    """Update website index.html — SUNGLASSES_STATS, JSON-LD, meta tags."""
    index = WEBSITE_ROOT / "index.html"
    if not index.exists():
        print("  SKIP website index.html — not found")
        return False

    replacements = [
        # SUNGLASSES_STATS JS config
        (r'patterns: \d+,', f'patterns: {stats["patterns"]},'),
        (r'categories: \d+,', f'categories: {stats["categories"]},'),
        (r'keywords: \d+,', f'keywords: {stats["keywords"]},'),
        (r'version: "[\d.]+"', f'version: "{stats["version"]}"'),
        # JSON-LD
        (r'"version": "[\d.]+"', f'"version": "{stats["version"]}"'),
        (r'"dateModified": "[\d-]+"', f'"dateModified": "{stats["date"]}"'),
        (r'("name": "detectionPatterns", "value": )\d+', rf'\g<1>{stats["patterns"]}'),
        (r'("name": "attackCategories", "value": )\d+', rf'\g<1>{stats["categories"]}'),
        (r'("name": "trackedKeywords", "value": )\d+', rf'\g<1>{stats["keywords"]}'),
        # Meta tags
        (r'(sunglasses:patterns" content=")\d+"', rf'\g<1>{stats["patterns"]}"'),
        (r'(sunglasses:categories" content=")\d+"', rf'\g<1>{stats["categories"]}"'),
        (r'(sunglasses:keywords" content=")\d+"', rf'\g<1>{stats["keywords"]}"'),
        (r'(sunglasses:version" content=")[\d.]+"', rf'\g<1>{stats["version"]}"'),
    ]
    return update_file(index, replacements, "website/index.html")


# The key each total goes by in stats/current.json (a total not listed is published as itself).
PUBLISHED_KEY = {"patterns": "detecting_patterns"}


def _previous_totals(stats):
    """The totals the site pages carry right now: explicit `_prev_*` values first, else the
    landing repo's stats/current.json. A key with no usable number stays None."""
    import json
    recorded = {}
    try:
        recorded = json.loads((WEBSITE_ROOT / "stats" / "current.json").read_text())
    except (OSError, ValueError):
        pass
    out = {}
    for key in ("patterns", "keywords", "categories"):
        raw = stats.get(f"_prev_{key}", recorded.get(PUBLISHED_KEY.get(key, key), recorded.get(key)))
        try:
            out[key] = int(str(raw).replace(",", ""))
        except (TypeError, ValueError):
            out[key] = None
    return out


def sync_website_pages(stats):
    """Update all other website pages with stale pattern/keyword/category counts."""
    if not WEBSITE_ROOT.exists():
        print("  SKIP website pages — directory not found")
        return False

    changed = False
    # Pattern for "N patterns, M keywords, K categories" in any order/format.
    # Counts must match stat-like numbers WITH the optional thousands comma —
    # the original \d{2,3}/\d{3} froze every page once patterns/keywords crossed
    # 1000 (4 digits): "1046 patterns" never matched \d{2,3}, so ~16 pages stuck
    # at a stale count through every ship (Jun 27 2026 root-cause fix). 3-6 char
    # numeric window (incl comma) covers 100..999,999; still avoids "3 patterns
    # per category". A specific previous value (set by the ship pipeline) is
    # preferred when available so only the real old count is rewritten.
    # THE PREVIOUS TOTAL IS THE ONLY NUMBER THIS RULE MAY REWRITE.
    # The old rule matched ANY 3-6 character number in front of "patterns", "keywords" or
    # "categories" whenever no previous value was passed in, and nothing ever passed one in.
    # Run by hand (Oct 16 2026, 18:12) it rewrote 13 per-chapter labels ("Chapter 01 · 156
    # patterns" -> "1569 patterns") and dropped the comma from "6,675 keywords". A chapter
    # count, a per-family count and a total are all "N patterns"; only the total is stale
    # when the catalog grows, and the total is known: it is what the site currently shows.
    # So the rule now rewrites a number only when it equals the previous total (an explicit
    # `_prev_*` value, else the landing repo's own stats/current.json, the file the release stamp
    # keeps), keeps the comma style of the text it replaces, and lists every other count it
    # looked at and left alone, so a skipped stale total is visible in the receipt, not silent.
    prev = _previous_totals(stats)
    shape = {
        "patterns": r"({n}|{nc}) ((?:detection )?patterns)\b",
        "keywords": r"({n}|{nc}) (keywords)\b",
        "categories": r"({n}|{nc}) ((?:threat |attack )?categories)\b",
    }
    generic_any = {
        "patterns": r"([\d,]{3,6}) ((?:detection )?patterns)\b",
        "keywords": r"([\d,]{3,6}) (keywords)\b",
        "categories": r"(\d{2,3}) ((?:threat |attack )?categories)\b",
    }

    def _style(old_text, value):
        return f"{value:,}" if "," in old_text else str(value)

    def _rewrite_for(key):
        def repl(m):
            return f"{_style(m.group(1), stats[key])} {m.group(2)}"
        return repl

    generic_replacements = []
    for key in ("patterns", "keywords", "categories"):
        n = prev.get(key)
        if n is None:
            print(f"  NOTE no previous {key} total known (no _prev_{key}, no stats/current.json): "
                  f"{key} counts on the site pages are left alone")
            continue
        rx = r"(?<![\d,.])" + shape[key].format(n=n, nc=f"{n:,}")
        generic_replacements.append((rx, _rewrite_for(key)))

    skipped = []

    def _note_skipped(rel, content):
        for key, rx in generic_any.items():
            for m in re.finditer(r"(?<![\d,.])" + rx, content):
                n = int(m.group(1).replace(",", ""))
                if n in (prev.get(key), stats[key]):
                    continue
                skipped.append((str(rel), m.group(0)))

    # A count is HISTORICAL (must NOT be rewritten) when its preceding text pins
    # it to a past release or frames it as a one-time delta — e.g. "v0.2.21
    # brought Sunglasses to 346 patterns", "0.2.31 (890 patterns, shipped
    # today)", "adds 10 patterns ... total 313 patterns". Rewriting those to
    # today's count falsifies history. We look back up to 60 chars from each
    # match; if it contains a version token or a historical verb, we leave it.
    # (Jun 27 2026 — sync-stats had been silently falsifying every past-release
    # claim; this guard plus the blog/reports skip makes a site-wide run safe.)
    HIST_LOOKBACK = 60
    _version_re = re.compile(r'\bv?\d+\.\d+\.\d+\b')
    _hist_verb_re = re.compile(
        r'\b(?:adds?|added|brought|bringing|grown|grew|shipped|ships|launch(?:ed|es)?|'
        r'release[ds]?|reached?|day\s*\d|after\s+day|as\s+of)\b', re.IGNORECASE)

    def _is_historical(text, start):
        window = text[max(0, start - HIST_LOOKBACK):start]
        return bool(_version_re.search(window) or _hist_verb_re.search(window))

    def _apply(content, pattern, repl):
        out, last = [], 0
        for m in re.finditer(pattern, content):
            out.append(content[last:m.start()])
            out.append(m.group(0) if _is_historical(content, m.start()) else repl(m))
            last = m.end()
        out.append(content[last:])
        return "".join(out)

    # Pages to scan (exclude index.html — handled separately).
    # CRITICAL: skip dated content (blog posts, published reports). Those make
    # point-in-time claims like "v0.2.21 brought Sunglasses to 346 patterns" —
    # blindly rewriting their counts to TODAY's value FALSIFIES history (a blog
    # would read "v0.2.21 ... 1059 patterns", which is false and a credibility
    # killer). Only EVERGREEN marketing pages get the live counts; dated
    # artifacts keep the numbers true as of their publish date. (Jun 27 2026 —
    # found sync-stats had been silently falsifying every historical blog.)
    DATED_DIRS = {"blog", "reports"}
    DATED_FILES = {"blog.html", "diary.html"}  # root-level dated indexes/journals

    def _is_dated(p):
        rel = p.relative_to(WEBSITE_ROOT)
        if set(rel.parts) & DATED_DIRS:
            return True
        if p.name in DATED_FILES:
            return True
        return p.name.startswith("report-")  # root-level published reports

    pages = [p for p in WEBSITE_ROOT.glob("**/*.html") if not _is_dated(p)]
    index_path = WEBSITE_ROOT / "index.html"

    for page in pages:
        if page == index_path:
            continue

        content = page.read_text()
        original = content

        for pattern, replacement in generic_replacements:
            content = _apply(content, pattern, replacement)
        _note_skipped(page.relative_to(WEBSITE_ROOT), content)

        if content != original:
            page.write_text(content)
            rel = page.relative_to(WEBSITE_ROOT)
            print(f"  UPDATED website/{rel}")
            changed = True

    if skipped:
        print(f"  SKIPPED {len(skipped)} count(s) that are not the previous total (per-chapter and "
              f"per-family counts are meant to differ; a stale TOTAL would show up here):")
        for rel, text in skipped[:40]:
            print(f"    {rel}: {text}")
        if len(skipped) > 40:
            print(f"    ... and {len(skipped) - 40} more")

    return changed


def main():
    print(f"\nSUNGLASSES Stats Sync")
    print(f"{'='*40}")

    stats = get_real_stats()
    print(f"\nSource of truth (patterns.py):")
    print(f"  Patterns:   {stats['patterns']}")
    print(f"  Categories: {stats['categories']}")
    print(f"  Keywords:   {stats['keywords']}")
    print(f"  Regex:      {stats['regex']}")
    print(f"  Version:    {stats['version']}")
    print(f"  Date:       {stats['date']}")
    print()

    changes = 0
    if sync_readme(stats): changes += 1
    if sync_website_index(stats): changes += 1
    if sync_website_pages(stats): changes += 1

    print(f"\n{'='*40}")
    if changes > 0:
        print(f"Done. {changes} file(s) updated. Review changes, then push.")
    else:
        print("Everything already in sync.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
