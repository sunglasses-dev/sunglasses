"""The second copy of a rule is the rule with its guards removed, and nothing else.

A rule that carries a guard (a negative lookahead that defuses it when a word shows up) has a second
copy that the engine builds on first use. That copy has to match exactly where the rule would match if
its guards were taken out by hand, so that a defused rule is kept in place one level lower and never
widened or narrowed in any other way.

What these tests hold, for every shipped rule:

  A. the reference below, which reads the parse tree of a regex and shares no code with the engine,
     removes the guards of small hand written regexes the way the engine does,
  B. the regexes of the second copy are the regexes of the rule with the reference's guards removed,
     compared as parse trees, so they match the same text,
  C. a rule has a second copy exactly when the reference finds a guard in it.
"""
import os
import sys

import pytest

try:
    from re import _constants as C, _parser as P
except ImportError:                                              # Python before 3.11
    import sre_constants as C                                    # noqa: F401
    import sre_parse as P                                        # noqa: F401

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from sunglasses.engine import _GUARD_FLOOR_EXTRA, _guard_floor_twin, _guard_free_source   # noqa: E402
from sunglasses.patterns import PATTERNS                                                  # noqa: E402

MAX = C.MAXREPEAT
LEAD_ANCHORS = (C.AT_BEGINNING, C.AT_BEGINNING_STRING)


def _flat(nodes):
    """The nodes with plain `(?:...)` groups opened up, whatever the Python version builds for them."""
    out = []
    for node in nodes:
        if node[0] is C.SUBPATTERN and node[1][0] is None and not node[1][1] and not node[1][2]:
            out.extend(_flat(node[1][3]))
        else:
            out.append(node)
    return out


def _is_blank_run(nodes):
    """The possessive blank run some rules put right after the caret: `(?=(\\s*))\\1`."""
    if len(nodes) < 2 or nodes[0][0] is not C.ASSERT or nodes[0][1][0] != 1 or nodes[1] != (C.GROUPREF, 1):
        return False
    body = _flat(nodes[0][1][1])
    if len(body) != 1 or body[0][0] is not C.SUBPATTERN or body[0][1][0] != 1:
        return False
    inner = _flat(body[0][1][3])
    if len(inner) != 1 or inner[0][0] is not C.MAX_REPEAT or inner[0][1][:2] != (0, MAX):
        return False
    return list(inner[0][1][2]) == [(C.IN, [(C.CATEGORY, C.CATEGORY_SPACE)])]


def _scans_ahead(body):
    """A negative lookahead that reads forward through the text with a dot or an any character class."""
    nodes = _flat(body)
    while nodes:
        first = nodes[0]
        if first[0] is C.SUBPATTERN:
            nodes = _flat(first[1][3])
        elif first[0] is C.ASSERT and first[1][0] == 1:
            nodes = _flat(first[1][1])
        else:
            break
    if not nodes or nodes[0][0] not in (C.MAX_REPEAT, C.MIN_REPEAT):
        return False
    low, high, inner = nodes[0][1]
    inner = _flat(inner)
    if len(inner) != 1:
        return False
    if inner[0][0] is C.ANY:
        return True
    if inner[0][0] is C.IN and sorted(map(repr, inner[0][1])) == sorted(map(repr, [
            (C.CATEGORY, C.CATEGORY_SPACE), (C.CATEGORY, C.CATEGORY_NOT_SPACE)])):
        return not (low == 1 and high == MAX) and not (low == 0 and high == 1)
    return False


def _shape(node, numbers):
    """A parse tree as plain tuples, with capture groups numbered in the order they open."""
    if isinstance(node, tuple) and len(node) == 2 and node[0] is C.SUBPATTERN:
        group, added, removed, inner = node[1]
        if group is not None:
            numbers.setdefault(group, len(numbers) + 1)
        return ("group", None if group is None else numbers[group], added, removed,
                tuple(_shape(item, numbers) for item in _flat(inner)))
    if isinstance(node, tuple) and len(node) == 2 and node[0] is C.GROUPREF:
        return ("ref", numbers.get(node[1], ("unopened", node[1])))
    if isinstance(node, (list, tuple, P.SubPattern)):
        return tuple(_shape(item, numbers) for item in node)
    return repr(node)


def reference_without_guards(source, scan_all=False):
    """(parse tree without the guards, flags), or None when the regex has no guard.

    A guard is a negative lookahead in the leading zone (every consecutive lookahead after the caret and
    the blank run), or one at the top level that scans forward through the text, or any one at the top
    level when `scan_all` is set. Positive lookaheads and length caps stay."""
    tree = P.parse(source)
    nodes = _flat(tree.data)
    drop, i = set(), 0
    if nodes and nodes[0][0] is C.AT and nodes[0][1] in LEAD_ANCHORS:
        i = 1
        if _is_blank_run(nodes[i:]):
            i += 2
        while i < len(nodes) and nodes[i][0] in (C.ASSERT, C.ASSERT_NOT) and nodes[i][1][0] == 1:
            if nodes[i][0] is C.ASSERT_NOT:
                drop.add(i)
            i += 1
    for j, node in enumerate(nodes):
        if node[0] is C.ASSERT_NOT and node[1][0] == 1 and j not in drop and (scan_all or _scans_ahead(node[1][1])):
            drop.add(j)
    if not drop:
        return None
    return _shape([n for j, n in enumerate(nodes) if j not in drop], {}), tree.state.flags


def _tree_of(source):
    tree = P.parse(source)
    return _shape(_flat(tree.data), {}), tree.state.flags


# ── A. the reference, on small regexes written for it ──────────────────────────────────────────────

HAND = [
    # (regex, scan_all, the regex with its guards taken out by hand, or None)
    (r"(?is)^(?!.*\bdocs\b)run it now", False, r"(?is)^run it now"),
    (r"(?is)^(?!.*\bdocs\b)(?=.*run)(?!.{0,40}test)it now", False, r"(?is)^(?=.*run)it now"),
    (r"(?i)^(?:(?=(\s*))\1)(?!.*docs)run it", False, r"(?i)^(?:(?=(\s*))\1)run it"),
    (r"(?is)run it now(?!.*\bdocs\b)", False, r"(?is)run it now"),
    (r"(?is)run it now(?!\s+docs)", False, None),
    (r"(?is)run it now(?!\s+docs)", True, r"(?is)run it now"),
    (r"(?is)^(?=.{0,500}$)run it", False, None),
    (r"(?i)(?<!never )run it now", False, None),
    (r"(?is)run (?:it|that)(?![\s\S]{0,30}docs) now", False, r"(?is)run (?:it|that) now"),
    # a closing bracket written first in a class is a member of it, with or without the caret
    (r"(?is)^(?!.*[])]docs)(?=run).*", False, r"(?is)^(?=run).*"),
    (r"(?is)^(?!.*[^])]docs)(?=run).*", False, r"(?is)^(?=run).*"),
    # in verbose mode a comment runs to the end of its line, and a hash inside a class is a member
    ("(?isx)^(?!.*docs # ) closes nothing\n)(?=run).*", False, "(?isx)^(?=run).*"),
    ("(?isx)^(?!.*[#]docs)(?=run).*", False, "(?isx)^(?=run).*"),
    # a bracket in a comment does not change how deep the next group sits
    ("(?isx)run it now # note (\n(?!.*docs)", False, "(?isx)run it now"),
    ("(?isx)run it now # note )\n(?!.*docs)", False, "(?isx)run it now"),
    # verbose mode has a scope: a group can turn it off inside a pattern that has it on, and a group
    # can turn it on in a pattern that does not, and a hash outside that group is an ordinary character
    ("(?x)^(?!(?-x:.*#docs))(?=run).*", False, "(?x)^(?=run).*"),
    ("^(?!.*#docs)(?x:run)", False, "^(?x:run)"),
    ("(?x)^(?!(?-x:.*#)docs # ) closes nothing\n)(?=run).*", False, "(?x)^(?=run).*"),
    ("^(?!(?x:.*docs # ( note\n)#end)(?=run).*", False, "^(?=run).*"),
]


@pytest.mark.parametrize("source, scan_all, by_hand", HAND)
def test_the_reference_removes_the_guards_of_a_regex_written_by_hand(source, scan_all, by_hand):
    got = reference_without_guards(source, scan_all)
    assert (got is None) == (by_hand is None)
    if by_hand is not None:
        assert got == _tree_of(by_hand)


@pytest.mark.parametrize("source, scan_all, by_hand", HAND)
def test_the_engine_removes_the_same_guards_of_a_regex_written_by_hand(source, scan_all, by_hand):
    free = _guard_free_source(source, scan_all)
    assert (free is None) == (by_hand is None)
    if by_hand is not None:
        assert _tree_of(free) == _tree_of(by_hand)


# ── B and C. every shipped rule ────────────────────────────────────────────────────────────────────

def _expected(pattern):
    scan_all = pattern["id"] in _GUARD_FLOOR_EXTRA
    found = [reference_without_guards(source, scan_all) for source in pattern.get("regex") or []]
    return [item for item in found if item is not None]


def _shipped_pattern_ids():
    return sorted({p["id"] for p in PATTERNS})


@pytest.mark.parametrize("rule_id", _shipped_pattern_ids())
def test_the_second_copy_of_a_rule_is_the_rule_without_its_guards(rule_id):
    for pattern in (p for p in PATTERNS if p["id"] == rule_id):
        twin = _guard_floor_twin(pattern)
        expected = _expected(pattern)
        if not expected:
            assert twin is None, f"{rule_id} has a second copy but the reference finds no guard"
            continue
        assert twin is not None, f"{rule_id} has a guard and no second copy"
        got = [_tree_of(source) for source in twin["regex"]]
        assert got == expected, rule_id
