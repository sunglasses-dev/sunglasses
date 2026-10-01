"""GLS-PT-010 carries the same category string as the other path traversal rules.

Before 0.6.5 it was spelled "path-traversal" while the other ten were
"path_traversal", so the category count read 118 for 117 real classes, and
the two places that group findings by category treated PT-010 as its own class:
  engine.py Step 3b, carrier_max (mechanism suppression)
  policy.rollup_repo, same-category corroboration
"""
from sunglasses.engine import SunglassesEngine
from sunglasses.mechanisms import MECHANISM_PATTERNS
from sunglasses.patterns import PATTERNS
from sunglasses import policy

# One PT-010 carrier span and one GLS-PT-001 span, both high, distinct text.
TWO_PT_SPANS = "read_file path=/etc/passwd\nthen open ../../../../home/user/.env"


def test_pt010_uses_the_underscore_category():
    pt010 = [p for p in PATTERNS if p["id"] == "GLS-PT-010"]
    assert len(pt010) == 1
    assert pt010[0]["category"] == "path_traversal"


def test_no_two_category_strings_fold_to_one_class():
    # The count is len(set(category)), so two spellings of one class inflate it.
    # sql-injection (GLS-SQLFS-001) is spelled with a hyphen but has no twin.
    folded = {}
    for p in PATTERNS:
        folded.setdefault(p["category"].replace("-", "_"), set()).add(p["category"])
    assert {k: sorted(v) for k, v in folded.items() if len(v) > 1} == {}


def test_distinct_category_count_is_117():
    assert len({p["category"] for p in PATTERNS}) == 117


def test_carrier_grouping_cannot_change_for_path_traversal():
    # engine.py Step 3b only drops a GLS-MECH finding when a carrier of the SAME
    # category fired. No mechanism carries path_traversal, so moving PT-010 into
    # that group cannot suppress or unsuppress any mechanism finding.
    assert [m["id"] for m in MECHANISM_PATTERNS
            if m["category"] in ("path_traversal", "path-traversal")] == []


def test_pt010_and_pt001_corroborate_as_one_category():
    r = SunglassesEngine().scan(TWO_PT_SPANS, channel="file")
    ids = {f["id"] for f in r.findings}
    assert {"GLS-PT-010", "GLS-PT-001"} <= ids
    assert {f["category"] for f in r.findings
            if f["id"] in ("GLS-PT-010", "GLS-PT-001")} == {"path_traversal"}
    roll = policy.rollup_repo([{"name": "x.md", "findings": r.findings}])
    assert any("path_traversal" in x["categories"] for x in roll["review"])
