"""A listed rule that can never produce a finding is not counted as a detecting one.

71 of the listed rules carry no regex and no indexed keyword, so the engine compiles
nothing for them and a scan can never report them. They stay listed (they are rows in
the ruleset and in the attack database), but the figure the project publishes as its
pattern count is the number that can fire.

Three things are pinned here:

* `info()` reports both numbers, and the detecting one is the listed rows minus the
  named rows below. The engine's built-in mechanism rules are not listed rows and are
  not in either number.
* A row that cannot fire has to be named in `CANNOT_FIRE`. A new empty row fails here
  until it is named, so the list cannot grow by accident.
* The list only shrinks. When a named row gets a matcher, this fails until the row is
  taken off the list, so the published count follows the rule instead of a stale name.
"""
import json
import pathlib

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

ROOT = pathlib.Path(__file__).resolve().parents[1]

CANNOT_FIRE = frozenset([
    "GLS-SMP-008",
    "GLS-V3-005",
    "GLS-V3-008",
    "GLS-V3-032",
    "GLS-V3-039",
    "GLS-V3-058",
    "GLS-V3-061",
    "GLS-V3-064",
    "GLS-V3-002",
    "GLS-V3-006",
    "GLS-V3-013",
    "GLS-V3-019",
    "GLS-V3-020",
    "GLS-V3-023",
    "GLS-V3-024",
    "GLS-V3-010",
    "GLS-V3-011",
    "GLS-V3-017",
    "GLS-V3-018",
    "GLS-V3-026",
    "GLS-V3-027",
    "GLS-V3-028",
    "GLS-V3-041",
    "GLS-V3-042",
    "GLS-V3-043",
    "GLS-V3-062",
    "GLS-V3-066",
    "GLS-V3-069",
    "GLS-V3-003",
    "GLS-V3-021",
    "GLS-V3-025",
    "GLS-V3-044",
    "GLS-V3-048",
    "GLS-V3-056",
    "GLS-V3-057",
    "GLS-V3-012",
    "GLS-V3-014",
    "GLS-V3-059",
    "GLS-V3-063",
    "GLS-V3-001",
    "GLS-V3-030",
    "GLS-V3-033",
    "GLS-V3-034",
    "GLS-V3-050",
    "GLS-V3-054",
    "GLS-V3-004",
    "GLS-V3-009",
    "GLS-V3-015",
    "GLS-V3-016",
    "GLS-V3-022",
    "GLS-V3-045",
    "GLS-V3-046",
    "GLS-V3-055",
    "GLS-V3-029",
    "GLS-V3-035",
    "GLS-V3-036",
    "GLS-V3-037",
    "GLS-V3-040",
    "GLS-V3-049",
    "GLS-V3-051",
    "GLS-V3-052",
    "GLS-V3-053",
    "GLS-V3-007",
    "GLS-V3-031",
    "GLS-V3-038",
    "GLS-V3-047",
    "GLS-V3-060",
    "GLS-V3-065",
    "GLS-V3-067",
    "GLS-V3-068",
    "GLS-V3-070",
])


def _matchers(engine):
    ids = set(engine._compiled_by_id)
    ids.update(p["id"] for hits in engine._keyword_to_patterns.values() for p in hits)
    return ids


def test_the_rows_without_a_matcher_are_exactly_the_named_ones():
    have = _matchers(SunglassesEngine())
    empty = {p["id"] for p in PATTERNS if p["id"] not in have}
    assert empty == CANNOT_FIRE, (
        f"new rows with no regex and no keyword: {sorted(empty - CANNOT_FIRE)}; "
        f"named rows that now have a matcher (remove them from CANNOT_FIRE): "
        f"{sorted(CANNOT_FIRE - empty)}")


def test_info_counts_only_the_rows_that_can_fire():
    info = SunglassesEngine().info()
    assert info["listed_patterns"] == len(PATTERNS)
    assert info["detecting_patterns"] == len(PATTERNS) - len(CANNOT_FIRE)
    assert "patterns" not in info


def test_a_named_row_has_no_finding_to_give():
    # Scanning a row's own name and description is the strongest chance the engine
    # has to match it; none of the named rows may appear in the findings.
    engine = SunglassesEngine()
    seen = set()
    for p in PATTERNS:
        if p["id"] in CANNOT_FIRE:
            result = engine.scan(f'{p["name"]}. {p["description"]}')
            seen.update(f["id"] for f in result.findings if f["id"] in CANNOT_FIRE)
    assert not seen


def test_a_custom_ruleset_counts_its_own_rows():
    live = {"id": "T-1", "name": "live", "category": "x", "severity": "high",
            "channel": ["message"], "description": "d", "keywords": ["zzqx marker phrase"]}
    empty = {"id": "T-2", "name": "empty", "category": "x", "severity": "high",
             "channel": ["message"], "description": "d"}
    info = SunglassesEngine(patterns=[live, empty]).info()
    assert (info["listed_patterns"], info["detecting_patterns"]) == (2, 1)


def test_the_published_stats_carry_both_numbers_and_not_the_old_key():
    stats = json.loads((ROOT / "stats" / "current.json").read_text())
    info = SunglassesEngine().info()
    assert stats["detecting_patterns"] == info["detecting_patterns"]
    assert stats["listed_patterns"] == info["listed_patterns"]
    assert "patterns" not in stats, "a reader of the old key must fail, not read a stale number"
