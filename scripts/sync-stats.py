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
    total = info["patterns"]
    categories = set(p["category"] for p in patterns)
    keyword_count = info["keywords"]  # unique keywords from engine
    regex_count = info["regex_patterns"]

    # Get version
    init_file = REPO_ROOT / "sunglasses" / "__init__.py"
    version = "0.0.0"
    for line in init_file.read_text().splitlines():
        if "__version__" in line:
            version = line.split('"')[1]
            break

    return {
        "patterns": total,
        "categories": len(categories),
        "keywords": keyword_count,
        "regex": regex_count,
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
        # Stats table
        (r'\| Patterns \| \d+ \|', f'| Patterns | {stats["patterns"]} |'),
        (r'\| Keywords \| \d+ \|', f'| Keywords | {stats["keywords"]} |'),
        (r'\| Attack categories \| \d+ \|', f'| Attack categories | {stats["categories"]} |'),
        # What Works Today header
        (r'What Works Today \(v[\d.]+\)', f'What Works Today (v{stats["version"]})'),
        # What Works Today line
        (r'Text scanning: \d+ patterns, \d+ keywords, 13 languages, \d+ attack categories',
         f'Text scanning: {stats["patterns"]} patterns, {stats["keywords"]} keywords, 13 languages, {stats["categories"]} attack categories'),
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
    old_pat = stats.get("_prev_patterns", r"[\d,]{3,6}")
    old_kw = stats.get("_prev_keywords", r"[\d,]{3,6}")
    old_cat = stats.get("_prev_categories", r"\d{2,3}")
    generic_replacements = [
        # "1046 patterns" / "1,046 detection patterns" — 3-6 char counts (incl comma)
        (rf'\b{old_pat} (detection )?patterns\b', lambda m: f'{stats["patterns"]} {m.group(1) or ""}patterns'),
        # "7653 keywords" / "7,653 keywords"
        (rf'\b{old_kw} keywords\b', lambda m: f'{stats["keywords"]} keywords'),
        # "65 categories" / "65 threat categories"
        (rf'\b{old_cat} (threat |attack )?categories\b', lambda m: f'{stats["categories"]} {m.group(1) or ""}categories'),
    ]

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

        if content != original:
            page.write_text(content)
            rel = page.relative_to(WEBSITE_ROOT)
            print(f"  UPDATED website/{rel}")
            changed = True

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
