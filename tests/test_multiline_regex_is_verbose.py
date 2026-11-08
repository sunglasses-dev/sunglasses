"""Static lint: a rule regex written over several lines must be compiled as verbose.

A rule source that holds a literal newline (indentation, one lookahead per line) only means
what its author wrote if it starts with the verbose flag, e.g. `(?x)`, `(?six)`, `(?isx)`.
Without the flag the newlines and the indentation are characters the text itself would have
to contain, so a rule can end up unable to match anything at all.

The test reads every shipped rule source (the pattern table and the mechanism table) and
holds the line as a ratchet:

  * a multi-line source without the verbose flag, and not listed in KNOWN_BROKEN, fails;
  * a KNOWN_BROKEN source that gains the flag fails (the xfail is strict), so the entry
    must be removed in the same change that fixes the rule.

KNOWN_BROKEN is meant to reach empty. New entries are not accepted.
"""
import re

import pytest

from sunglasses.mechanisms import MECHANISM_PATTERNS
from sunglasses.patterns import PATTERNS

# Rule ids whose multi-line source is not verbose today (index = position in "regex").
KNOWN_BROKEN = {
    ("GLS-DFP-026", 0): "multi-line source without the verbose flag",
    ("GLS-DFP-048", 0): "multi-line source without the verbose flag",
}

_LEADING_FLAGS = re.compile(r"\(\?([aiLmsux]+)\)")

# The pattern table and the mechanism table are the two places rule sources live.
_RECORDS = list(PATTERNS) + list(MECHANISM_PATTERNS)


def has_verbose_flag(source):
    """True when the source opens with a global inline flag group that includes `x`."""
    match = _LEADING_FLAGS.match(source)
    return bool(match and "x" in match.group(1))


def multi_line_sources(records):
    """Yield (rule id, regex index, source) for every source holding a literal newline."""
    for record in records:
        for index, source in enumerate(record.get("regex") or []):
            if isinstance(source, str) and "\n" in source:
                yield record["id"], index, source


def offenders(records):
    """(rule id, regex index) of every multi-line source that is not verbose."""
    return [
        (rule_id, index)
        for rule_id, index, source in multi_line_sources(records)
        if not has_verbose_flag(source)
    ]


def _params():
    for rule_id, index, source in multi_line_sources(_RECORDS):
        marks = []
        if (rule_id, index) in KNOWN_BROKEN:
            marks.append(pytest.mark.xfail(
                strict=True,
                reason="known: " + KNOWN_BROKEN[(rule_id, index)],
            ))
        yield pytest.param(rule_id, index, source, id=f"{rule_id}[{index}]", marks=marks)


@pytest.mark.parametrize("rule_id,index,source", list(_params()))
def test_a_multi_line_source_is_verbose(rule_id, index, source):
    assert has_verbose_flag(source), (
        f"{rule_id} regex[{index}] holds a newline but does not start with a verbose flag, "
        "so its newlines and indentation are literal characters the text must contain"
    )


def test_the_known_broken_list_names_only_sources_that_exist():
    present = {(rule_id, index) for rule_id, index, _ in multi_line_sources(_RECORDS)}
    assert set(KNOWN_BROKEN) <= present


def test_the_scan_sees_the_multi_line_sources():
    # Floor, not an exact count: the lint must not pass because it read nothing.
    assert len(list(multi_line_sources(_RECORDS))) >= 100


def test_a_source_with_a_newline_and_no_verbose_flag_is_an_offender():
    records = [{"id": "X-1", "regex": ["(?i)a\nb"]}]
    assert offenders(records) == [("X-1", 0)]


def test_a_single_line_source_that_gains_a_newline_is_an_offender():
    plain = "(?i)abc|def"
    assert offenders([{"id": "X-2", "regex": [plain]}]) == []
    assert offenders([{"id": "X-2", "regex": [plain.replace("|", "\n|")]}]) == [("X-2", 0)]


@pytest.mark.parametrize("flags", ["(?x)", "(?six)", "(?isx)", "(?xi)"])
def test_a_leading_verbose_flag_passes(flags):
    assert offenders([{"id": "X-3", "regex": [flags + "\n  a\n  b"]}]) == []


def test_an_escaped_newline_is_not_a_newline():
    # backslash + n inside the source is a pattern escape, not a line break
    assert offenders([{"id": "X-4", "regex": ["(?i)a\\nb"]}]) == []


def test_the_x_must_be_in_the_leading_flag_group():
    assert offenders([{"id": "X-5", "regex": ["a\n(?x)b"]}]) == [("X-5", 0)]
    assert offenders([{"id": "X-5", "regex": ["(?i)a(?x)\nb"]}]) == [("X-5", 0)]
