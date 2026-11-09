"""Lab findings B1 (beyond the repaired entry) and E3 are open limits, and the
public list of known gaps must say so until they are repaired.

Plain tests over the rows in KNOWN_VERSION_GAPS.md. They fail if a row is
removed while the limit it describes is still open. When a repair ships, update
the row in the same change and delete the matching assertion here.

The slow-entry limit is not re-tested here: the timed check from lab finding B1
(tests/test_lab_b1_quadratic_whitespace_gate.py) already lists each open entry
as a strict expected failure. The look-alike limit (lab finding E3) has no
behavioral test in this tree on purpose: a public test would have to spell out
which letters pass, and the row states the limit without listing them.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GAPS = (ROOT / "KNOWN_VERSION_GAPS.md").read_text(encoding="utf-8")

SLOW_ENTRIES = ("GLS-CICD-004",)


@pytest.mark.parametrize("rule_id", SLOW_ENTRIES)
def test_each_open_slow_entry_is_listed(rule_id):
    assert re.search(rf"`{rule_id}`", GAPS), f"{rule_id} is missing from KNOWN_VERSION_GAPS.md"


def test_lookalike_limit_is_listed_in_one_line_with_the_fold_mechanism():
    rows = [
        line
        for line in GAPS.splitlines()
        if re.search(r"look-alike|confusab|homoglyph", line, re.I)
        and re.search(r"NFKC|table", line)
    ]
    assert rows, "the look-alike limit is missing from KNOWN_VERSION_GAPS.md"


def test_the_unbounded_proxy_id_records_are_listed_with_the_bounded_sibling():
    assert "## Documented bound" in GAPS
    section = GAPS[GAPS.index("## Documented bound"):]
    assert "TOMBSTONE_LIMIT" in section
    assert "left unbounded" in section


def test_the_manifest_path_false_positives_are_listed_until_the_fix_ships():
    # C1066: remove this test in the change that ships the C1065 fix (GLS-PT-001, GLS-CI-007), together with its paragraph.
    for rule_id in ("GLS-PT-001", "GLS-CI-007"):
        assert rule_id in GAPS, f"{rule_id} is missing from KNOWN_VERSION_GAPS.md"
    assert "581 of 5,691" in GAPS


def test_the_comment_text_false_positives_are_listed_until_the_fix_ships():
    # C1066: remove this test in the change that ships the C1069 fix (GLS-TS-251, GLS-GHSA-PI-202, GLS-APIP-005), together with its paragraph.
    for rule_id in ("GLS-TS-251", "GLS-GHSA-PI-202", "GLS-APIP-005"):
        assert rule_id in GAPS, f"{rule_id} is missing from KNOWN_VERSION_GAPS.md"
    assert "20 of 298" in GAPS
