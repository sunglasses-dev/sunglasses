#!/usr/bin/env python3
"""Count the languages SUNGLASSES actually ships patterns for, from the patterns.

The README claimed "23 languages" in four places. That number counted every
language NAMED anywhere in the ruleset as though it were covered, and a reader
takes "23 languages" to mean the scanner works in 23 languages. It does not.
Thirteen languages have exactly two dedicated patterns each.

The deeper defect was not the number, it was that the number had no generator.
A hand-written count is corrected once and then drifts back, because nothing
recomputes it. This script is the source; `stats/current.json` records what it
measured; tests/test_language_claims.py fails if a document disagrees with it.

    python3 tools/gen_language_stats.py            # print the measurement
    python3 tools/gen_language_stats.py --write    # update stats/current.json

Deliberately stdlib only.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sunglasses.patterns import PATTERNS  # noqa: E402

# A dedicated pattern announces its language in the first words of its
# description, e.g. "Russian-language credential exfiltration attempt."
MARKER = re.compile(r"\b([A-Z][a-z]+)-language\b")

# "<Word>-language" is also ordinary English. These are the non-language words
# seen in the corpus; an unrecognised one is REPORTED rather than silently
# counted or silently dropped, so a real language cannot go missing here.
NOT_A_LANGUAGE = {"Natural", "Cross", "Multi", "Plain", "Machine", "Query", "Markup"}


def measure(patterns=PATTERNS) -> dict:
    per_language: dict[str, int] = {}
    unknown: dict[str, int] = {}
    for p in patterns:
        for word in MARKER.findall(p.get("description", "") or ""):
            if word in NOT_A_LANGUAGE:
                unknown[word] = unknown.get(word, 0) + 1
            else:
                per_language[word] = per_language.get(word, 0) + 1
    return {
        "dedicated_pattern_languages": len(per_language),
        "dedicated_patterns_per_language": dict(sorted(per_language.items())),
        "non_language_markers_seen": dict(sorted(unknown.items())),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="write the measurement into stats/current.json")
    args = ap.parse_args()
    m = measure()

    print(f"dedicated-pattern languages: {m['dedicated_pattern_languages']}")
    for lang, n in m["dedicated_patterns_per_language"].items():
        print(f"  {lang:12s} {n} pattern(s)")
    if m["non_language_markers_seen"]:
        print("\nnot counted as languages (report, so nothing is lost silently):")
        for w, n in m["non_language_markers_seen"].items():
            print(f"  {w}-language x{n}")

    if args.write:
        sp = ROOT / "stats" / "current.json"
        stats = json.loads(sp.read_text())
        # `languages: 23` is retired. It was one number doing two jobs: how many
        # languages have patterns, and how many are named anywhere. Typed fields
        # cannot be read as the other thing by accident.
        stats.pop("languages", None)
        stats["dedicated_pattern_languages"] = m["dedicated_pattern_languages"]
        stats["dedicated_patterns_per_language"] = m["dedicated_patterns_per_language"]
        stats["language_stats_generated_by"] = "tools/gen_language_stats.py"
        sp.write_text(json.dumps(stats, indent=2) + "\n")
        print(f"\nwrote {sp.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
