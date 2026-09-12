"""Assertions that cannot fail are worse than missing tests.

A missing test is a known gap. An assertion that always passes is a gap wearing
a green tick, and it gets cited as proof.

Both patterns below were found in this repository's own tests by an external
reviewer, not by us:

  An assertion ending in `or True`. Written while reaching for a comparison that
  was awkward to express, left in, and it made a preservation check vacuous.
  Disabling the rule it claimed to protect left every test green.

  A loop that iterates channels but omits a live one. The same preservation
  check walked `file`, `web_content` and `tool_output` and never `message`, so
  removing five `message` bindings changed nothing visible.

This module is a lint over the test suite itself. It is cheap, it runs with the
rest of the suite, and it exists because a reviewer should not be the first
thing standing between a vacuous assertion and a merge.
"""
import ast
import pathlib

import pytest

TESTS_DIR = pathlib.Path(__file__).resolve().parent

# Every channel the engine accepts. A test that enumerates channels and silently
# omits one of these is asserting less than it appears to.
LIVE_CHANNELS = {
    "message", "file", "api_response", "web_content", "log_memory",
    "tool_output", "agent_input", "code", "prompt",
}

# Channel sets a test may legitimately iterate without naming every channel:
# the CLI surface, and the four used by the recovered STATE #39 specimens.
SANCTIONED_SUBSETS = [
    {"message", "file", "api_response", "web_content", "log_memory"},
    {"message", "file", "api_response", "tool_output"},
    # WO-P1B round 4 splits the channels deliberately: six parent rules keep the
    # existing channels with parent behaviour, and six siblings carry the new
    # reach alone. Each half MUST be tested without the other, because the point
    # of the split is that neither touches the other's territory. A test that
    # iterated all seven here would be unable to express that.
    {"api_response", "log_memory", "agent_input"},          # the siblings' own
    {"message", "file", "web_content", "tool_output"},      # the parents' own
]


def _test_files():
    return sorted(p for p in TESTS_DIR.glob("test_*.py")
                  if p.name != pathlib.Path(__file__).name)


def _is_always_true(node: ast.AST) -> bool:
    """True when this expression can never be falsy."""
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return any(_is_always_true(v) for v in node.values)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return all(_is_always_true(v) for v in node.values)
    return False


@pytest.mark.parametrize("path", _test_files(), ids=lambda p: p.name)
def test_no_assertion_is_unconditionally_true(path):
    """`assert <anything> or True` is a comment with a green tick on it."""
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert) and _is_always_true(node.test):
            offenders.append(node.lineno)
    assert not offenders, (
        f"{path.name} has assertion(s) that can never fail, at line(s) "
        f"{offenders}. An assertion that cannot fail does not protect anything "
        "and will be cited as if it did."
    )


@pytest.mark.parametrize("path", _test_files(), ids=lambda p: p.name)
def test_channel_lists_do_not_silently_omit_a_live_channel(path):
    """A channel loop that skips a live channel tests less than it looks like."""
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            continue
        names = {e.value for e in node.elts
                 if isinstance(e, ast.Constant) and isinstance(e.value, str)}
        known = names & LIVE_CHANNELS
        # Only judge collections that are clearly channel lists.
        if len(known) < 3 or known != names:
            continue
        if known in SANCTIONED_SUBSETS or known == LIVE_CHANNELS:
            continue
        missing = sorted(
            c for c in ("message", "file", "api_response", "tool_output")
            if c not in known)
        if missing:
            offenders.append((node.lineno, sorted(known), missing))
    assert not offenders, (
        f"{path.name} iterates a partial channel list: {offenders}. "
        "If the omission is deliberate, add the set to SANCTIONED_SUBSETS with "
        "the reason; otherwise the test is silent about the channel it skips."
    )


def test_this_lint_actually_catches_both_shapes(tmp_path):
    """The lint is a gate, so it is proven by what it rejects."""
    vacuous = tmp_path / "test_vacuous_sample.py"
    vacuous.write_text(
        "def test_x():\n"
        "    value = 1\n"
        "    assert value == 2 or True\n")
    tree = ast.parse(vacuous.read_text())
    found = [n.lineno for n in ast.walk(tree)
             if isinstance(n, ast.Assert) and _is_always_true(n.test)]
    assert found == [3], "the lint no longer detects `or True`"

    partial = tmp_path / "test_partial_sample.py"
    partial.write_text(
        'CHANNELS = ["file", "web_content", "tool_output"]\n')
    tree = ast.parse(partial.read_text())
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            names = {e.value for e in node.elts
                     if isinstance(e, ast.Constant) and isinstance(e.value, str)}
            known = names & LIVE_CHANNELS
            if len(known) >= 3 and known == names and "message" not in known:
                hits.append(node.lineno)
    assert hits == [1], "the lint no longer detects a channel list missing message"
