"""The attack-db README's counts must be the counts of the scanner it describes.

`attack-db/README.md` carried three hand-typed figures ("1048 detection
patterns", "1059 patterns / 65 categories", "its 65 categories") while
`sunglasses/patterns.py` held 1554 rules in 118 categories. The mirror parity
test keeps the JSON honest; nothing read the prose beside it, so the numbers
stopped moving the day somebody stopped typing them.

The truth here is `PATTERNS`, the same list the exporter reads, so a figure in
the README agrees with the scanner or this fails and names the line. Categories
are counted by rule, not by folder: the exporter folds two category names into
one folder, and the root README already says 118.
"""
import pathlib
import re

from sunglasses.patterns import PATTERNS

README = pathlib.Path(__file__).resolve().parents[1] / "attack-db" / "README.md"

# Every place the README states a count, in any of the shapes it has used.
_PATTERN_COUNT = re.compile(r"\b(\d[\d,]*)\s+(?:detection\s+)?patterns\b", re.I)
_CATEGORY_COUNT = re.compile(r"\b(\d[\d,]*)\s+(?:attack\s+)?categories\b", re.I)


def _stated(text, rx):
    return [(n, int(m.group(1).replace(",", "")))
            for n, line in enumerate(text.splitlines(), 1)
            for m in rx.finditer(line)]


def test_every_pattern_count_in_the_readme_is_the_scanners():
    stated = _stated(README.read_text(), _PATTERN_COUNT)
    assert stated, "the README states no pattern count, so this measured nothing"
    wrong = [(line, n) for line, n in stated if n != len(PATTERNS)]
    assert not wrong, (
        f"attack-db/README.md states pattern counts that are not "
        f"len(PATTERNS) == {len(PATTERNS)}: (line, stated) {wrong}")


def test_every_category_count_in_the_readme_is_the_scanners():
    truth = len({p["category"] for p in PATTERNS})
    stated = _stated(README.read_text(), _CATEGORY_COUNT)
    assert stated, "the README states no category count, so this measured nothing"
    wrong = [(line, n) for line, n in stated if n != truth]
    assert not wrong, (
        f"attack-db/README.md states category counts that are not the "
        f"{truth} distinct categories in PATTERNS: (line, stated) {wrong}")


def test_the_reader_sees_every_shape_the_readme_has_used():
    """The control: each stale sentence that shipped must be read as a count."""
    old = ("**1048 detection patterns across 65 attack categories.**\n"
           "(1059 patterns / 65 categories)\n"
           "Sunglasses organizes its 65 categories across families\n"
           "1,554 patterns across 118 categories\n")
    assert [n for _, n in _stated(old, _PATTERN_COUNT)] == [1048, 1059, 1554]
    assert [n for _, n in _stated(old, _CATEGORY_COUNT)] == [65, 65, 65, 118]
