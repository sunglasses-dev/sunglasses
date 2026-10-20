#!/usr/bin/env python3
"""
Export sunglasses/taxonomy.py -> attack-db/TAXONOMY.md

Single source of truth: sunglasses/taxonomy.py (it ships in the package; attack-db does not).
This script renders the same table as a page a person can read next to the patterns.
tests/test_taxonomy.py fails if the committed page differs from what this prints.

Usage:
    python scripts/export_taxonomy_to_attack_db.py

Safety: READ-ONLY on taxonomy.py. Only writes attack-db/TAXONOMY.md.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sunglasses import taxonomy

OUT = os.path.join(os.path.dirname(__file__), "..", "attack-db", "TAXONOMY.md")


def _cell(entries, link=None):
    return "<br>".join(
        f"[{e['id']}]({link(e['id'])}) {e['name']}" if link else f"{e['id']} {e['name']}"
        for e in entries
    )


def render():
    src = taxonomy.SOURCES
    lines = [
        "# Attack categories and the public frameworks they sit under",
        "",
        "Every finding's `category` maps to entries in three published lists. `sunglasses scan "
        "--json` carries them on each finding as `taxonomy`, and SARIF output carries them as "
        "`taxonomies` with a `relationships` entry on each rule.",
        "",
        "This is a category-level mapping. It says which headings an attack of this kind is "
        "discussed under, not that one finding is a confirmed instance of a technique. A category "
        "can touch more than one heading, and some headings are a loose fit; the closest entries "
        "that exist in each list were chosen and no identifier is invented. It is data that "
        "annotates output. It is never read when the scanner decides.",
        "",
        "Generated from [`sunglasses/taxonomy.py`](../sunglasses/taxonomy.py) by "
        "`scripts/export_taxonomy_to_attack_db.py`. Do not edit by hand.",
        "",
        "## Sources",
        "",
    ]
    for key in ("owasp_llm_top10", "mitre_atlas", "nist_ai"):
        s = src[key]
        lines.append(f"- {s['name']}, {s['version']}: <{s['url']}>")
    lines += [
        "",
        "## Mapping",
        "",
        "| Category | OWASP LLM Top 10 (2025) | MITRE ATLAS (2026.09) | NIST AI RMF / AI 600-1 |",
        "|---|---|---|---|",
    ]
    for category in taxonomy.categories():
        t = taxonomy.for_category(category)
        lines.append(
            f"| `{category}` | {_cell(t['owasp_llm_top10'], taxonomy.owasp_url)} "
            f"| {_cell(t['mitre_atlas'])} | {_cell(t['nist_ai'])} |"
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(render())
    print(f"Wrote {len(taxonomy.categories())} categories to attack-db/TAXONOMY.md")
