"""Static lint: a rule regex must not stack two unbounded wide repeats on one match path.

Rule regexes should use bounded repeats (`.{0,200}`) or the tempered form
(`(?:(?!A).)*A`) rather than two open-ended `.*` in a row. This test reads the parsed form
of every rule regex and holds the line as a ratchet:

  * a rule id that shows the shape and is NOT in GRANDFATHERED fails the build;
  * a GRANDFATHERED id that no longer shows the shape fails the build, so a rewritten
    rule must leave the list and the list only shrinks.

GRANDFATHERED is meant to reach empty. It is not empty today: take ids off it as the
rewrites merge.

"Wide" means a single-node repeat body that can match nearly any character: `.`, a
negated class, a negated single character, or a class holding both halves of \\s \\S,
\\d \\D or \\w \\W. Lookaround bodies are checked on their own path.
"""
import re

import pytest

try:  # Python 3.11+ moved the parser
    from re import _constants as C
    from re import _parser as P
except ImportError:  # Python 3.9 / 3.10
    import sre_constants as C
    import sre_parse as P

from sunglasses.mechanisms import MECHANISM_PATTERNS
from sunglasses.patterns import PATTERNS

UNBOUNDED = C.MAXREPEAT
_ATOMIC = getattr(C, "ATOMIC_GROUP", None)
_POSSESSIVE = getattr(C, "POSSESSIVE_REPEAT", None)
_REPEATS = (C.MAX_REPEAT, C.MIN_REPEAT)

_REWRITE_PENDING = "2026-10-19 rewrite to a single read is in review"
_REVIEWED = "2026-10-18 reviewed, no action needed"
_UNREVIEWED = "2026-10-19 shape present, not yet reviewed for input cost"

GRANDFATHERED = {
    "GLS-AW-585": _REWRITE_PENDING,
    "GLS-DFP-035": _REWRITE_PENDING,
    "GLS-MR-038": _REWRITE_PENDING,
    "GLS-ADP-002": _REVIEWED,
}
GRANDFATHERED.update(dict.fromkeys((
    "GLS-ABX-008", "GLS-AIFP-008", "GLS-ALP-005", "GLS-APIP-006", "GLS-APIP-010",
    "GLS-AW-616", "GLS-AW-617", "GLS-AW-621", "GLS-AW-655", "GLS-AW-691",
    "GLS-AW-722", "GLS-AW-743", "GLS-BMP-001", "GLS-BMP-009", "GLS-CAI-279",
    "GLS-CAI-695", "GLS-CI-007", "GLS-CMP-010", "GLS-DFP-020", "GLS-DFP-032",
    "GLS-DFP-034", "GLS-DFP-037", "GLS-DFP-039", "GLS-DFP-042", "GLS-DFP-043",
    "GLS-DFP-045", "GLS-DFP-047", "GLS-DFP-054", "GLS-DFP-058", "GLS-DFP-081",
    "GLS-DFP-086", "GLS-DFP-091", "GLS-DFP-119", "GLS-DFP-127", "GLS-DFP-144",
    "GLS-DKS-002", "GLS-DKS-003", "GLS-EX-011", "GLS-IP-003", "GLS-MCP-016",
    "GLS-MCP-030", "GLS-MCP-046", "GLS-MCP-047", "GLS-MCP-049", "GLS-MCP-055",
    "GLS-MCP-056", "GLS-MCP-079", "GLS-MM-AUDIO-206", "GLS-RMP-001",
    "GLS-RMP-005", "GLS-RMP-006", "GLS-RPD-006", "GLS-SC-003", "GLS-SC-005",
    "GLS-SC-008", "GLS-SC-023", "GLS-SCAP-001", "GLS-SDH-001", "GLS-SEM-UI-219",
    "GLS-SI-001", "GLS-SMP-001", "GLS-SMP-002", "GLS-SMP-006", "GLS-SMP-018",
    "GLS-SPI-001", "GLS-SQLFS-001", "GLS-TOP-639",
), _UNREVIEWED))


def _wide(body):
    """True when the repeated body is one node that can match almost any character."""
    if len(body) != 1:
        return False
    op, av = body[0]
    if op in (C.ANY, C.NOT_LITERAL):
        return True
    if op != C.IN:
        return False
    if any(o == C.NEGATE for o, _ in av):
        return True
    cats = {a for o, a in av if o == C.CATEGORY}
    halves = ((C.CATEGORY_SPACE, C.CATEGORY_NOT_SPACE),
              (C.CATEGORY_DIGIT, C.CATEGORY_NOT_DIGIT),
              (C.CATEGORY_WORD, C.CATEGORY_NOT_WORD))
    return any(a in cats and b in cats for a, b in halves)


def _path_repeats(seq):
    """Most wide unbounded repeats that one match path through seq can run in sequence."""
    n = 0
    for op, av in seq:
        if op in _REPEATS:
            _lo, hi, body = av
            inner = _path_repeats(body)
            if hi >= UNBOUNDED and _wide(body):
                n += 1
            elif inner and hi > 1:
                n += 2 * inner  # a repeated group re-enters its inner repeat
            else:
                n += inner
        elif op == C.SUBPATTERN:
            n += _path_repeats(av[3])
        elif op == C.BRANCH:
            n += max([_path_repeats(b) for b in av[1]] + [0])
        elif _ATOMIC is not None and op == _ATOMIC:
            n += _path_repeats(av)
        elif _POSSESSIVE is not None and op == _POSSESSIVE:
            _lo, hi, body = av
            n += _path_repeats(body) + (1 if hi >= UNBOUNDED and _wide(body) else 0)
        elif op == C.GROUPREF_EXISTS:
            n += max(_path_repeats(av[1]), _path_repeats(av[2]) if av[2] else 0)
        # ASSERT / ASSERT_NOT run separately: _worst() checks their bodies on their own
    return n


def _worst(seq):
    """Max over the main path and the path inside every lookaround, however deep."""
    worst = _path_repeats(seq)
    stack = [seq]
    while stack:
        cur = stack.pop()
        for op, av in cur:
            if op in (C.ASSERT, C.ASSERT_NOT):
                worst = max(worst, _path_repeats(av[1]))
                stack.append(av[1])
            elif op in _REPEATS:
                stack.append(av[2])
            elif op == C.SUBPATTERN:
                stack.append(av[3])
            elif op == C.BRANCH:
                stack.extend(av[1])
    return worst


def has_stacked_repeats(source):
    return _worst(P.parse(source, re.IGNORECASE)) >= 2


def _flagged_ids():
    flagged = set()
    for rule in (*PATTERNS, *MECHANISM_PATTERNS):
        if any(has_stacked_repeats(src) for src in rule.get("regex") or ()):
            flagged.add(rule["id"])
    return flagged


@pytest.mark.parametrize("source", [
    r".*a.*b",
    r".*a.+b",
    r".*?a.*?b",
    r"[\s\S]*a[\s\S]*b",
    r"[^x]*a[^x]*b",
    r"(?:.*a)+b",
    r"(?=.*a.*b)",
    r"x(?:.*a|b).*c",
])
def test_walker_flags_stacked_wide_repeats(source):
    assert has_stacked_repeats(source)


@pytest.mark.parametrize("source", [
    r"(?:(?!a).)*a.*b",
    r".{0,200}a.{0,200}b",
    r"(?=.*a)(?=.*b)",
    r"(?:.*a|.*b)c",
    r"\w+\s*x\s+y",
    r"a.*b",
    r"[a-z]*a[a-z]*b",
])
def test_walker_passes_bounded_shapes(source):
    assert not has_stacked_repeats(source)


def test_new_rules_do_not_stack_unbounded_repeats():
    new = sorted(_flagged_ids() - set(GRANDFATHERED))
    assert not new, (
        "these rule ids run two unbounded wide repeats along one match path: %s. "
        "Bound the first repeat (`.{0,200}`), use the tempered form `(?:(?!X).)*X`, or "
        "move the second condition into a lookahead. Do not add to GRANDFATHERED."
        % ", ".join(new)
    )


def test_grandfathered_ids_still_show_the_shape():
    stale = sorted(set(GRANDFATHERED) - _flagged_ids())
    assert not stale, (
        "these ids no longer show the shape (or no longer exist): %s. "
        "Remove them from GRANDFATHERED so the list keeps shrinking." % ", ".join(stale)
    )


def test_every_grandfathered_entry_carries_a_dated_reason():
    for rule_id, reason in GRANDFATHERED.items():
        assert re.match(r"20\d\d-\d\d-\d\d ", reason), rule_id
