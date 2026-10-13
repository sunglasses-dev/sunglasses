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

SLOW_ENTRIES = ("GLS-AW-001", "GLS-SC-018", "GLS-CF-251", "GLS-CICD-004", "GLS-AW-713")


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
