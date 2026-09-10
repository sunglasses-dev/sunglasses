"""
test_firewall_policy_action_surface.py — the POLICY lane's false-positive gate.

Why this file exists, stated plainly because the history is the point:

`tests/test_firewall_fp.py` is a good gate. It carries 78 real-world READMEs and
a 40-doc clean corpus, and it smuggles them through tool calls as heredocs —
which is EXACTLY the shape that broke us. It never caught this bug, for one
reason: every assertion in it calls `check_egress_secrets`. The policy lane,
`check_policy`, was never wired to a corpus at all.

So on 2026-08-28 the firewall denied two agents for writing prose that NAMED a
protected path, the class was written down, and nothing failed in CI — because
nothing in CI was asking the policy lane anything. Thirteen days later, on
2026-09-10, it denied three agents inside ten minutes, including one who was
writing the analysis of the bug at the time.

The fix under test is `_action_surface`: a path rule asks "does this call TOUCH
that path?", so the lane now reads the fields that can act — `file_path` for
the file tools, the command for Bash with literal heredoc bodies removed and
executable substitutions inside unquoted bodies kept — instead of every value.

Two bars, both blocking:
  * PROSE THAT MENTIONS a protected path must be ALLOWED. Documentation about a
    policy is not an attempt on it.
  * A CALL THAT TOUCHES a protected path must still be DENIED, on every carrier.
    Fixing an FP by gutting the detector is the other half of the lesson.

The corpus replay reuses `fp_corpus_data.CLEAN_CORPUS` deliberately: the same
documents the secrets lane already trusts, now asked of the lane that denied us.
"""
import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses.firewall import bash_action_surface, check_policy  # noqa: E402

# A synthetic protected path. Never a real one from anybody's policy: a test
# that depends on the operator's own secrets layout is a test that breaks on a
# different machine, and it puts a live path into the repository for no gain.
BLOCKED = "/tmp/p1a-fixture/secret.key"
POLICY = {"blocked_paths": [BLOCKED]}


def denied(tool_name, tool_input):
    return check_policy(tool_name, tool_input, POLICY) is not None


# ---------------------------------------------------------------------------
# MENTIONS must be allowed. These are the three real denials from 2026-09-10,
# reduced to their shapes: a Write whose body names the path, a Bash heredoc
# whose body names it, and an Edit that documents it.
# ---------------------------------------------------------------------------
MENTIONS = [
    ("write-body-names-path",
     "Write", {"file_path": "/tmp/README.md",
               "content": f"Never commit anything to {BLOCKED} in this repo"}),
    ("edit-newstring-names-path",
     "Edit", {"file_path": "/tmp/README.md", "old_string": "x",
              "new_string": f"The policy protects {BLOCKED} from every tool"}),
    ("bash-quoted-heredoc-names-path",
     "Bash", {"command": f"cat > /tmp/notes.md <<'EOF'\nsee {BLOCKED}\nEOF"}),
    ("bash-quoted-heredoc-multiline-doc",
     "Bash", {"command": f"cat > /tmp/d.md <<'EOF'\n# Policy\n- {BLOCKED} is blocked\n- rotate quarterly\nEOF"}),
    ("notebook-source-names-path",
     "NotebookEdit", {"notebook_path": "/tmp/n.ipynb",
                      "new_source": f"# do not read {BLOCKED}"}),
]


@pytest.mark.parametrize("name,tool,inp", MENTIONS, ids=[m[0] for m in MENTIONS])
def test_mentioning_a_blocked_path_is_not_touching_it(name, tool, inp):
    assert not denied(tool, inp), (
        f"{name}: prose that NAMES {BLOCKED} was denied as if it touched it — "
        "this is the 08-28/09-10 regression"
    )


# ---------------------------------------------------------------------------
# TOUCHES must still be denied, on every carrier. If any of these ever passes,
# the FP was 'fixed' by blinding the lane.
# ---------------------------------------------------------------------------
TOUCHES = [
    ("write-target", "Write", {"file_path": BLOCKED, "content": "x"}),
    ("edit-target", "Edit", {"file_path": BLOCKED, "old_string": "a", "new_string": "b"}),
    ("read-target", "Read", {"file_path": BLOCKED}),
    ("notebook-target", "NotebookEdit", {"notebook_path": BLOCKED, "new_source": "x"}),
    ("bash-plain", "Bash", {"command": f"cat {BLOCKED}"}),
    ("bash-heredoc-redirect-target", "Bash",
     {"command": f"cat > {BLOCKED} <<'EOF'\nx\nEOF"}),
    ("bash-unquoted-heredoc-substitution", "Bash",
     {"command": f"cat > /tmp/n.md <<EOF\n$(cat {BLOCKED})\nEOF"}),
    ("bash-unquoted-heredoc-backticks", "Bash",
     {"command": f"cat > /tmp/n.md <<EOF\n`cat {BLOCKED}`\nEOF"}),
    ("bash-unterminated-heredoc-is-uncertain", "Bash",
     {"command": f"cat > /tmp/n.md <<'EOF'\n{BLOCKED}\n"}),
    ("unknown-tool-keeps-old-behaviour", "Frobnicate", {"payload": BLOCKED}),
]


@pytest.mark.parametrize("name,tool,inp", TOUCHES, ids=[t[0] for t in TOUCHES])
def test_touching_a_blocked_path_is_still_denied(name, tool, inp):
    assert denied(tool, inp), (
        f"{name}: a call that TOUCHES {BLOCKED} was allowed — the FP fix has "
        "blinded the policy lane"
    )


def test_an_uncertain_parse_is_never_reported_as_safe():
    """An unterminated heredoc means we do not know where the body ends."""
    command = f"cat > /tmp/n.md <<'EOF'\nharmless prose about {BLOCKED}\n"
    assert bash_action_surface(command) == command
    assert denied("Bash", {"command": command})


# ---------------------------------------------------------------------------
# CORPUS REPLAY — the documents the secrets lane already trusts, asked of the
# lane that denied us. This is the wiring that was missing: the corpus was
# always there, the policy lane was never pointed at it.
# ---------------------------------------------------------------------------
def _clean_corpus():
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    from fp_corpus_data import CLEAN_CORPUS
    return CLEAN_CORPUS


def test_clean_corpus_through_a_write_body_is_never_a_policy_denial():
    hits = [i for i, doc in enumerate(_clean_corpus())
            if denied("Write", {"file_path": "/tmp/doc.md", "content": doc})]
    assert not hits, f"policy lane denied clean corpus docs by INDEX {hits[:5]}"


def test_clean_corpus_through_a_quoted_heredoc_is_never_a_policy_denial():
    hits = [i for i, doc in enumerate(_clean_corpus())
            if denied("Bash", {"command": f"cat > /tmp/doc.md <<'EOF'\n{doc}\nEOF"})]
    assert not hits, f"policy lane denied heredoc-carried corpus docs by INDEX {hits[:5]}"


def test_our_own_documentation_is_in_the_corpus_shape():
    """The case that actually bit us: our docs describing our own policy.

    The corpus is full of other people's READMEs. It contained nothing that
    talks about Sunglasses' own blocked_paths, which is the exact document
    three agents were writing when the firewall stopped them.
    """
    self_referential = [
        f"blocked_paths:\n  - {BLOCKED}\n\nAny tool call that touches one of these is denied.",
        f"The firewall denied a Write because the prose named {BLOCKED} and nothing was touched",
        f"To change this, edit the policy file and remove {BLOCKED} from the list",
    ]
    for doc in self_referential:
        assert not denied("Write", {"file_path": "/tmp/POLICY.md", "content": doc})
        assert not denied("Bash", {"command": f"cat > /tmp/P.md <<'EOF'\n{doc}\nEOF"})
