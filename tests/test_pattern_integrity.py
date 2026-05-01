"""Pattern catalog integrity guards.

Locks doors that have been broken before:
  - Duplicate IDs (live as of v0.2.27: GLS-EX-001, GLS-SE-001, GLS-TP-002 — fixed v0.2.28)
  - category=None (live as of v0.2.27 audit: 155/444 patterns — fixed v0.2.28)
  - Missing IDs

If any pattern is added without an id or category, or with a colliding id,
the build fails here before it can reach PyPI.
"""

from collections import Counter

from sunglasses.patterns import PATTERNS


def test_no_duplicate_pattern_ids():
    ids = [p["id"] for p in PATTERNS if "id" in p]
    counts = Counter(ids)
    dupes = {k: v for k, v in counts.items() if v > 1}
    assert not dupes, f"Duplicate pattern IDs found: {dupes}"


def test_every_pattern_has_an_id():
    missing = [i for i, p in enumerate(PATTERNS) if not p.get("id")]
    assert not missing, f"{len(missing)} pattern(s) missing 'id' field at indices: {missing[:10]}"


def test_every_pattern_has_a_category():
    missing = [p.get("id", "<no-id>") for p in PATTERNS if not p.get("category")]
    assert not missing, f"{len(missing)} pattern(s) missing/None category. First 10: {missing[:10]}"


def test_every_pattern_has_a_name():
    missing = [p.get("id", "<no-id>") for p in PATTERNS if not p.get("name")]
    assert not missing, f"{len(missing)} pattern(s) missing 'name' field. First 10: {missing[:10]}"


def test_pattern_id_format():
    """All pattern IDs follow GLS-<PREFIX>(-<SUBPREFIX>)?-<NNN>.

    Accepts 3-segment IDs (GLS-EX-001) and 4-segment multilingual IDs (GLS-ML-RU-001).
    """
    import re
    pattern = re.compile(r"^GLS(-[A-Z0-9]+){2,3}$")
    bad = [p["id"] for p in PATTERNS if not pattern.match(p.get("id", ""))]
    assert not bad, f"{len(bad)} pattern ID(s) violate GLS-<PREFIX>-...-<NNN> shape. First 10: {bad[:10]}"
