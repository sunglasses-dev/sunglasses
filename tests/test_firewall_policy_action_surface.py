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


# ---------------------------------------------------------------------------
# PRESERVED BEHAVIOUR — narrowing the surface must not quietly drop any of the
# properties the lane already had. ASTRA's acceptance list names these four.
# ---------------------------------------------------------------------------
HOME_POLICY = {"blocked_paths": ["~/.p1a-fixture-creds"]}


def test_home_variable_handling_survives():
    """`$HOME`, `${HOME}` and `~` all still resolve to the same rule."""
    for carrier in ("~/.p1a-fixture-creds/key",
                    "$HOME/.p1a-fixture-creds/key",
                    "${HOME}/.p1a-fixture-creds/key"):
        assert check_policy("Read", {"file_path": carrier}, HOME_POLICY) is not None, carrier
    # and the prose form is still allowed
    assert check_policy(
        "Write",
        {"file_path": "/tmp/doc.md", "content": "we protect $HOME/.p1a-fixture-creds/key here"},
        HOME_POLICY,
    ) is None


def test_directory_boundary_check_survives():
    """`~/.p1a-fixture-creds` covers the directory, never a sibling prefix."""
    assert check_policy("Read", {"file_path": "~/.p1a-fixture-creds/key"}, HOME_POLICY) is not None
    assert check_policy("Read", {"file_path": "~/.p1a-fixture-creds-backup/key"}, HOME_POLICY) is None


def test_a_path_containing_spaces_is_handled_as_before():
    """The token regex stops at whitespace, so a spaced path is not captured.

    This is pre-existing behaviour and narrowing the surface must not change
    it in either direction: the point of the test is that the fix is not what
    introduced the limitation, and that it is written down rather than assumed.
    """
    spaced = {"blocked_paths": ["/tmp/p1a fixture/secret.key"]}
    assert check_policy("Read", {"file_path": "/tmp/p1a fixture/secret.key"}, spaced) is None


def test_unknown_tool_controls_survive():
    """A tool we do not model keeps the old all-values behaviour, both ways."""
    assert check_policy("Frobnicate", {"anything": BLOCKED}, POLICY) is not None
    assert check_policy("Frobnicate", {"anything": "/tmp/harmless"}, POLICY) is None


def test_empty_and_missing_inputs_do_not_crash():
    for inp in ({}, None, {"file_path": ""}, {"command": ""}):
        assert check_policy("Write", inp, POLICY) is None
        assert check_policy("Bash", inp, POLICY) is None


# ---------------------------------------------------------------------------
# END TO END — the PUBLIC hook, in a disposable project, with harmless marker
# operations. ASTRA's acceptance requires proving that allowed work actually
# proceeds and denied work actually does not execute, not merely that a
# function returned a verdict.
# ---------------------------------------------------------------------------
import json
import os
import subprocess
import tempfile


def _run_public_hook(project, tool_name, tool_input):
    """Invoke `python3 -m sunglasses.firewall` exactly as Claude Code does."""
    env = dict(os.environ)
    env["SUNGLASSES_HOME"] = str(project / "sunglasses-home")
    payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses.firewall"],
        input=payload, capture_output=True, text=True, env=env,
        cwd=str(pathlib.Path(__file__).resolve().parents[1]),
    )
    assert proc.returncode == 0, f"hook exited {proc.returncode}: {proc.stderr[:400]}"
    return json.loads(proc.stdout or "{}")


def _decision_of(out):
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision")


def test_public_hook_allows_writing_about_a_blocked_path_and_the_work_happens():
    with tempfile.TemporaryDirectory() as tmp:
        project = pathlib.Path(tmp)
        home = project / "sunglasses-home"
        home.mkdir()
        secret = project / "vault" / "secret.key"
        (home / "policy.yaml").write_text(f"blocked_paths:\n  - {secret}\n")

        marker = project / "NOTES.md"
        prose = f"Our policy blocks {secret} and this note only mentions it"

        out = _run_public_hook(project, "Write", {"file_path": str(marker), "content": prose})
        assert _decision_of(out) != "deny", f"public hook denied prose: {out}"

        # The harmless marker operation the hook just allowed, actually performed.
        marker.write_text(prose)
        assert marker.exists() and str(secret) in marker.read_text()


def test_public_hook_denies_writing_to_a_blocked_path_and_the_work_does_not_happen():
    with tempfile.TemporaryDirectory() as tmp:
        project = pathlib.Path(tmp)
        home = project / "sunglasses-home"
        home.mkdir()
        vault = project / "vault"
        vault.mkdir()
        secret = vault / "secret.key"
        (home / "policy.yaml").write_text(f"blocked_paths:\n  - {vault}\n")

        out = _run_public_hook(project, "Write", {"file_path": str(secret), "content": "x"})
        assert _decision_of(out) == "deny", f"public hook allowed a real target: {out}"

        # Denied means the operation is not performed. Nothing wrote the file.
        assert not secret.exists(), "a denied call left its artefact on disk"
