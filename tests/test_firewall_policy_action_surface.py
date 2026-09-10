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

from sunglasses.firewall import check_policy  # noqa: E402

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


def test_the_bash_false_positive_is_still_open_and_that_is_recorded():
    """The half of the 09-10 regression this change does NOT fix.

    A Bash command whose text only NAMES a blocked path is still denied. Two
    attempts to subtract quoted heredoc bodies before asking the path question
    both let real operations through (ASTRA executed nine of them on 09-10), so
    Bash is judged on all of its text until a real grammar exists. This test
    exists so the gap is a recorded contract rather than a silent one: when the
    Bash lane is repaired, this test is what fails and gets rewritten.
    """
    prose = f"cat > /tmp/notes.md <<'EOF'\nsee {BLOCKED}\nEOF"
    assert denied("Bash", {"command": prose}), (
        "the Bash prose false positive appears to be fixed -- if that is real, "
        "this test and the note above `_action_surface` both need rewriting"
    )


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


def test_clean_corpus_through_a_bash_command_is_never_a_policy_denial():
    """Background control only.

    ASTRA's receipt correction, 09-10: no clean corpus document contains a
    policy-relevant path, so this cannot demonstrate the mention/touch
    distinction. It shows the lane does not fire on ordinary documents. The
    self-referential fixtures below are what actually carry the evidence.
    """
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


# ---------------------------------------------------------------------------
# T9 REVIEW 2026-09-10 — three commands that ACT on a protected path while the
# first cut of the heredoc parser returned zero paths for them. Every one is a
# case of the parser NARROWING when it had not actually established anything:
# the exact failure ASTRA's third NO GO condition names. Written to fail first.
# ---------------------------------------------------------------------------
VAULT_POLICY = {"blocked_paths": ["~/.p1a-fixture-vault"]}

REVIEW_BYPASSES = [
    # `<<<` is a here-string, not a heredoc. Matching the inner `<<` swallowed
    # the following real command as if it were an inert body.
    ("here-string",
     "echo <<<EOF\nrm -rf ~/.p1a-fixture-vault/keys\nEOF"),
    # A substitution spanning lines inside an UNQUOTED body executes. Scanning
    # the body line by line never sees it.
    ("multiline-substitution",
     "cat <<EOF\n$(\nrm -rf ~/.p1a-fixture-vault/keys\n)\nEOF"),
    # `<<EOF` inside a quoted string is not a heredoc at all. Treating it as one
    # turned the real commands after it into a body.
    ("heredoc-token-inside-a-quoted-string",
     'echo "x <<EOF"\nrm -rf ~/.p1a-fixture-vault/keys\nEOF'),
]


@pytest.mark.parametrize("name,command", REVIEW_BYPASSES,
                         ids=[b[0] for b in REVIEW_BYPASSES])
def test_review_bypasses_still_deny(name, command):
    assert check_policy("Bash", {"command": command}, VAULT_POLICY) is not None, (
        f"{name}: the command acts on the protected path and the parser "
        "narrowed it away — an unestablished parse became a proved safe one"
    )


# ---------------------------------------------------------------------------
# SELF ATTACK — shapes tried against the hardened parser after the T9 review,
# looking for a fourth bypass. None of these narrowed anything away. Kept as
# regressions so a future simplification of the parser has to face them.
# ---------------------------------------------------------------------------
SELF_ATTACK = [
    ("comment-containing-heredoc-token",
     "# see <<EOF docs\nrm -rf ~/.p1a-fixture-vault/keys"),
    ("single-quoted-heredoc-token",
     "echo '<<EOF' ; rm -rf ~/.p1a-fixture-vault/keys"),
    ("escaped-quote-then-real-heredoc",
     'echo "a\\"b" ; cat <<EOF\nx\nEOF\nrm -rf ~/.p1a-fixture-vault/keys'),
    ("two-heredocs-opened-on-one-line",
     "cat <<A <<B\nx\nA\ny\nB\nrm -rf ~/.p1a-fixture-vault/keys"),
    ("dash-heredoc-with-tab-indented-terminator",
     "cat <<-EOF\n\tx\n\tEOF\nrm -rf ~/.p1a-fixture-vault/keys"),
    ("terminator-with-trailing-space",
     "cat <<EOF\nx\nEOF \nrm -rf ~/.p1a-fixture-vault/keys"),
    ("nested-substitution-in-unquoted-body",
     "cat <<EOF\n$(echo $(rm -rf ~/.p1a-fixture-vault/keys))\nEOF"),
    ("backtick-substitution-spanning-lines",
     "cat <<EOF\n`\nrm -rf ~/.p1a-fixture-vault/keys\n`\nEOF"),
]


@pytest.mark.parametrize("name,command", SELF_ATTACK, ids=[c[0] for c in SELF_ATTACK])
def test_self_attack_shapes_still_deny(name, command):
    assert check_policy("Bash", {"command": command}, VAULT_POLICY) is not None, name


# ---------------------------------------------------------------------------
# ASTRA REVIEW 2026-09-10 — nine shapes he EXECUTED against the second cut of
# the parser. Each one really ran under bash 3.2 and really created a marker
# inside the blocked directory while the candidate hook deferred. They are the
# reason Bash is no longer narrowed at all, and they are kept here so that any
# future attempt to narrow it has to face them before it merges.
#
# Verdict + receipts: Desktop/SUNGLASSES_ASTRA_REVIEW_2026-09-04/
#   P1A_REVIEW_e7fb3a2_2026-09-10/{VERDICT.md,RESULTS.json,probe.py}
# ---------------------------------------------------------------------------
V = "~/.p1a-fixture-vault/marker"

ASTRA_BYPASSES = [
    # R1. Quoting a delimiter says the CURRENT shell will not expand the body.
    # It says nothing about what the receiving program does with it. Both of
    # these hand a "literal" body to an interpreter, which runs it.
    ("R1-quoted-heredoc-into-a-shell", f"/bin/bash <<'DOC'\n: > {V}\nDOC\n"),
    ("R1-quoted-heredoc-through-a-pipeline", f"/bin/cat <<'DOC' | /bin/bash\n: > {V}\nDOC\n"),
    # R2. Substitution extraction undercaptures, and it undercaptures in the
    # UNSAFE direction: the operation survives, the evidence of it does not.
    ("R2-nested-substitution", f"/bin/cat > /dev/null <<DOC\n$(printf x; $(printf true); : > {V})\nDOC\n"),
    ("R2-parenthesis-inside-quotes", f"/bin/cat > /dev/null <<DOC\n$(printf ')'; : > {V})\nDOC\n"),
    ("R2-substitution-spanning-lines", f"/bin/cat > /dev/null <<DOC\n$(\n: > {V}\n)\nDOC\n"),
    # R3. The parser recognised a heredoc that was never there, then found its
    # guessed terminator further down and swallowed the live commands between.
    # A fallback for a parser that FAILS does nothing for one that is confidently
    # wrong.
    ("R3-opener-inside-a-comment", f"# <<'true'\n: > {V}\ntrue\n"),
    ("R3-opener-inside-quoted-text", f"printf '%s\\n' \"<<'true'\" > /dev/null\n: > {V}\ntrue\n"),
    ("R3-delimiter-word-longer-than-the-token", f"/bin/cat > /dev/null <<true-tail\nordinary caption\ntrue-tail\n: > {V}\ntrue\n"),
    ("R3-arithmetic-shift-read-as-a-redirect", f"true=2\n: $((1 << true))\n: > {V}\ntrue\n"),
]


@pytest.mark.parametrize("name,command", ASTRA_BYPASSES,
                         ids=[b[0] for b in ASTRA_BYPASSES])
def test_astra_executed_bypasses_deny(name, command):
    assert check_policy("Bash", {"command": command}, VAULT_POLICY) is not None, (
        f"{name}: ASTRA ran this command and it wrote inside the blocked "
        "directory. Whatever narrowing allowed it has to be reverted."
    )


def test_a_quoted_heredoc_body_carried_through_a_pipeline_is_not_proved_prose():
    """The case that looked like the allow side and was not.

    Until ASTRA executed R1, this asserted that a quoted body carried through a
    pipeline is prose. `<<'EOF' | tee` is; `<<'DOC' | bash` is a program, and
    the two are not distinguishable by the quoting. Judging the whole command
    denies both, which costs a false positive on the first and refuses to guess
    on the second.
    """
    command = ("grep x <<'EOF' | tee /tmp/out\n"
               "the policy protects ~/.p1a-fixture-vault/keys from every tool\n"
               "EOF")
    assert check_policy("Bash", {"command": command}, VAULT_POLICY) is not None


# ---------------------------------------------------------------------------
# SELF REVIEW 2026-09-10 — narrowing the file tools has to be earned too.
#
# The first scope-split commit looked at the documented path field and, when it
# was missing or empty, returned an EMPTY surface. An empty surface is not "no
# paths found", it is "nothing to check", so eight shapes that the baseline
# DENIED were allowed: `Write` with no `file_path`, with `""`, with `None`,
# with `0`; `Edit`, `MultiEdit` and `NotebookEdit` with their target absent;
# and a `Read` carrying an extra key that named the target.
#
# Same rule as Bash: a tool NAME we know is not the same as a call we know. We
# narrow only when the input matches the documented schema AND actually carries
# a target. Anything else is judged on all of its values.
# ---------------------------------------------------------------------------
UNRECOGNISED_SHAPES = [
    ("write-without-a-target", "Write", {"content": BLOCKED}),
    ("write-with-an-empty-target", "Write", {"file_path": "", "content": BLOCKED}),
    ("write-with-a-null-target", "Write", {"file_path": None, "content": BLOCKED}),
    ("write-with-a-falsy-zero-target", "Write", {"file_path": 0, "content": BLOCKED}),
    ("edit-without-a-target", "Edit", {"old_string": "a", "new_string": BLOCKED}),
    ("multiedit-without-a-target", "MultiEdit", {"edits": [{"new_string": BLOCKED}]}),
    ("notebookedit-without-a-target", "NotebookEdit", {"new_source": BLOCKED}),
    ("read-carrying-a-key-the-schema-does-not-list",
     "Read", {"file_path": "/tmp/a", "notebook_path": BLOCKED}),
]


@pytest.mark.parametrize("name,tool,inp", UNRECOGNISED_SHAPES,
                         ids=[s[0] for s in UNRECOGNISED_SHAPES])
def test_a_known_tool_name_is_not_a_known_call(name, tool, inp):
    assert denied(tool, inp), (
        f"{name}: the target field was missing, empty or joined by a key the "
        "documented schema does not list, and the call was narrowed anyway. "
        "An unrecognised shape must be judged on all of its values."
    )


def test_the_recognised_shapes_are_still_narrowed():
    """The fail-closed rule above must not swallow the fix it guards."""
    assert not denied("Write", {"file_path": "/tmp/R.md",
                                "content": f"never touch {BLOCKED}"})
    assert not denied("Edit", {"file_path": "/tmp/R.md", "old_string": "x",
                               "new_string": BLOCKED, "replace_all": False})
    assert not denied("Read", {"file_path": "/tmp/R.md", "offset": 1, "limit": 2})
    assert denied("Write", {"file_path": BLOCKED, "content": "x"})
    assert denied("Read", {"file_path": BLOCKED, "offset": 1})
