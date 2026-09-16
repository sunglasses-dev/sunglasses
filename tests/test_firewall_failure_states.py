"""
test_firewall_failure_states.py — A DEAD CONTROL MUST SAY SO (RED 4).

Every state below used to end the same way: the policy lane produced no opinion,
the hook emitted `{}`, and the call fell through to the normal permission flow
with nothing on screen to say the control was down.

`{}` is indistinguishable from "I looked and this is fine". That is the defect.
A firewall that is quietly off looks exactly like one that checked and found
nothing, and the user has no way to tell which they are living with.

Each state now ASKS, and the question names which control died. Asking is
deliberately annoying; the fix is to repair the policy, not to learn to click
through. Each fixture below is paired with a MUTATION that restores the old
fall-through, so none of these can quietly regress to `{}`.

F1 policy missing · F2 corrupt · F3 unreadable · F4 empty · F5 not a mapping
F6 the audit trail cannot be written
"""
import json
import os
import pathlib
import tempfile

import pytest

from sunglasses import firewall
from sunglasses.firewall import PolicyDown, run_hook, starter_policy_text

CLEAN = json.dumps({
    "hook_event_name": "PreToolUse", "tool_name": "Bash",
    "tool_input": {"command": "echo hello"}, "session_id": "failure-states",
})
# Built rather than written literally: a Bash command whose TEXT names a blocked
# path is denied by our own firewall, which is a documented limit of this repo.
SECRET_PATH = "~/." + "ssh/id_" + "rsa"
DENIED = json.dumps({
    "hook_event_name": "PreToolUse", "tool_name": "Read",
    "tool_input": {"file_path": SECRET_PATH}, "session_id": "failure-states",
})


def _decision(home, payload=CLEAN):
    out = run_hook(payload, home=home).get("hookSpecificOutput", {})
    return out.get("permissionDecision"), out.get("permissionDecisionReason", "")


# A tool this install has never seen, so the pin lane has to decide.
NEW_MCP_CALL = json.dumps({
    "session_id": "round4",
    "tool_name": "mcp__github__create_issue",
    "tool_input": {},
})


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "sunglasses-home"
    h.mkdir()
    return h


def _healthy(home):
    (home / "policy.yaml").write_text(starter_policy_text(enabled=True))
    return home


# ── F1..F5: the policy file ──────────────────────────────────────────────────

STATES = [
    ("F1_missing",    None,                    "gone"),
    ("F2_corrupt",    "blocked_paths: [\n",    "does not parse"),
    ("F3_unreadable", "__CHMOD__",             "cannot be read"),
    ("F4_empty",      "   \n\n",               "is empty"),
]


@pytest.mark.parametrize("label,content,phrase", STATES, ids=[s[0] for s in STATES])
def test_a_dead_policy_asks_and_names_the_control(home, label, content, phrase):
    path = home / "policy.yaml"
    # A missing policy is only a DEAD control where one was installed. The marker
    # is what says so; without it a machine that never ran `init` would be asked
    # on every call forever, which is the cry-wolf failure this must not become.
    (home / firewall.INSTALL_MARKER).write_text("installed here\n")
    if content == "__CHMOD__":
        path.write_text(starter_policy_text(enabled=True))
        os.chmod(path, 0o000)
    elif content is not None:
        path.write_text(content)
    try:
        action, reason = _decision(home)
    finally:
        if content == "__CHMOD__":
            os.chmod(path, 0o600)
    assert action == "ask", f"{label}: a dead control must ask, got {action!r}"
    assert phrase in reason, f"{label}: the reason must name the state, got {reason!r}"
    assert "policy" in reason.lower(), f"{label}: the reason must name the control"


def test_a_machine_that_never_installed_a_policy_is_not_nagged(home):
    """No marker, no policy, no noise.

    `write_receipt` creates the home directory itself on the first call, so
    "the directory exists" is not evidence a policy was ever configured. The
    first draft of this feature used exactly that signal and would have asked
    on every call on a fresh machine.
    """
    action, _ = _decision(home)
    assert action is None, (
        f"an unconfigured machine must stay silent, got {action!r}"
    )


def test_a_healthy_policy_is_unchanged(home):
    """The whole value of asking depends on not asking the rest of the time."""
    action, _ = _decision(_healthy(home))
    assert action is None, (
        f"a working policy must still fall through silently, got {action!r}; "
        "a firewall that asks on every ordinary call gets clicked through"
    )


def test_f5_a_policy_that_is_not_a_mapping_is_rejected():
    """Defence in depth, and honest about it.

    The shipped parser raises on a list document, so this state is not reachable
    through `load_policy` today. The check exists so that a future parser change
    cannot turn a non-mapping policy into an attribute error at hook time.
    """
    original = firewall.parse_policy
    firewall.parse_policy = lambda _text: ["not", "a", "mapping"]
    try:
        home = pathlib.Path(tempfile.mkdtemp()) / "home"
        home.mkdir()
        (home / "policy.yaml").write_text("anything\n")
        with pytest.raises(PolicyDown) as caught:
            firewall.load_policy(home / "policy.yaml")
        assert caught.value.state == "wrong_type"
    finally:
        firewall.parse_policy = original


# ── F6: the audit trail ──────────────────────────────────────────────────────

def _break_receipts(home):
    """A plain file where the receipts directory belongs.

    Not a chmod: `write_receipt` repairs a loose directory mode by design, so a
    mode-only failure self-heals and is not an unwritable state at all.
    """
    (home / "receipts").write_text("not a directory\n")


def test_f6_an_unrecordable_call_asks(home):
    _healthy(home)
    _break_receipts(home)
    action, reason = _decision(home)
    assert action == "ask"
    assert "audit trail" in reason, reason


def test_f6_a_block_stays_a_block_when_the_audit_trail_is_down(home):
    """Losing an audit line must not WEAKEN a decision.

    Upgrading a deny to an ask because the disk is full would turn a storage
    problem into a security downgrade.
    """
    _healthy(home)
    _break_receipts(home)
    action, _ = _decision(home, DENIED)
    assert action == "deny", f"a block must survive an unwritable audit trail, got {action!r}"


# ── MUTATIONS: each one restores the silent fall-through ─────────────────────

@pytest.mark.parametrize("label,content", [(s[0], s[1]) for s in STATES],
                         ids=[s[0] for s in STATES])
def test_control_the_old_fall_through_returns_empty_for_every_state(home, label, content):
    """The world before this change, one state at a time.

    `load_policy` used to answer `{}` for an absent file and raise a generic
    error for the rest, both of which ended as `{}` on the wire. With that
    behaviour restored every state below goes silent again, which is what makes
    the assertions above worth anything.
    """
    path = home / "policy.yaml"
    if content == "__CHMOD__":
        path.write_text(starter_policy_text(enabled=True))
        os.chmod(path, 0o000)
    elif content is not None:
        path.write_text(content)

    original = firewall.load_policy
    firewall.load_policy = lambda _p: {}          # the old silent answer
    try:
        action, _ = _decision(home)
    finally:
        firewall.load_policy = original
        if content == "__CHMOD__":
            os.chmod(path, 0o600)
    assert action is None, (
        f"{label}: with the old behaviour restored this must fall through silently; "
        "if it does not, these tests are not measuring the change they claim to"
    )


def test_control_the_old_receipt_handling_swallows_an_unwritable_trail(home):
    _healthy(home)
    _break_receipts(home)
    original = firewall.write_receipt
    firewall.write_receipt = lambda *a, **k: None   # the old "pass" on failure
    try:
        action, _ = _decision(home)
    finally:
        firewall.write_receipt = original
    assert action is None, (
        "with the failure swallowed the call goes silent again, which is the "
        "behaviour F6 replaces"
    )


# ── round 2 R1: bytes that do not decode are F3, not an escaped exception ────
# `read_text` raises UnicodeDecodeError, which is a ValueError and NOT an
# OSError, so undecodable policy bytes went straight past the unreadable clause
# and out of the named-failure lane altogether. The hook returned `{}` with no
# stated state, and the same exception took the later pin TOFU decision with it.
# Two junk bytes at the end of the file were enough.

UNDECODABLE = b"blocked_paths:\n\xff\xfe"


def _write_bytes(home, data):
    (home / "policy.yaml").write_bytes(data)
    (home / firewall.INSTALL_MARKER).write_text("enrolled\n")
    return home


def test_undecodable_policy_bytes_are_classified_as_unreadable(home):
    _write_bytes(home, UNDECODABLE)
    with pytest.raises(PolicyDown) as caught:
        firewall.load_policy(home / "policy.yaml")
    assert caught.value.state == "unreadable", (
        f"undecodable bytes were classified as {caught.value.state!r}"
    )


def test_undecodable_policy_bytes_ask_and_name_the_control(home):
    _write_bytes(home, UNDECODABLE)
    decision, reason = _decision(home)
    assert decision == "ask", f"got {decision!r}, so the dead control was silent"
    assert "cannot be read" in reason, reason
    assert "did NOT run" in reason, reason


def test_undecodable_policy_bytes_do_not_take_the_rest_of_the_hook_down(home):
    """The whole point of a named state: later lanes still get to decide."""
    _write_bytes(home, UNDECODABLE)
    out = run_hook(CLEAN, home=home)
    assert out.get("hookSpecificOutput"), "the hook produced no decision at all"
    # and the failure is recorded rather than swallowed
    assert "cannot be read" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_swallowing_the_classification_brings_the_silence_back(home, monkeypatch):
    """Mutation control. Remove UnicodeError from the clause and this must fail.

    Without it the exception escapes `load_policy` entirely, which is exactly
    the state round 1 shipped in.
    """
    _write_bytes(home, UNDECODABLE)
    real = firewall.load_policy

    def only_oserror(path):
        p = pathlib.Path(path)
        try:
            p.read_text()
        except OSError as exc:                     # the pre-fix clause
            raise PolicyDown("unreadable", str(exc)) from exc
        return real(path)

    monkeypatch.setattr(firewall, "load_policy", only_oserror)
    with pytest.raises(UnicodeDecodeError):
        firewall.load_policy(home / "policy.yaml")


# ── round 2 R3: an install that predates the marker must still enrol ─────────
# The marker is what turns a LATER missing policy into a dead control rather
# than a machine that never configured one. It was only written on the branch
# that CREATES policy.yaml, so every install that already had a policy took an
# early return and never got it. Those are precisely the older installs.

LEGACY_SHAPES = [
    ("a policy the user wrote", "blocked_paths: []\n"),
    ("our own untouched disabled starter", None),   # filled in at call time
]


@pytest.mark.parametrize("label,body", LEGACY_SHAPES, ids=[s[0] for s in LEGACY_SHAPES])
def test_an_existing_install_is_enrolled_by_init_policy(home, label, body):
    text = starter_policy_text(enabled=False) if body is None else body
    (home / "policy.yaml").write_text(text, encoding="utf-8")
    assert not (home / firewall.INSTALL_MARKER).exists()

    firewall.write_starter_policy(home=home, enabled=True)

    assert (home / firewall.INSTALL_MARKER).exists(), (
        f"{label}: init --policy left this install unenrolled, so losing the "
        "policy later still falls through silently"
    )


@pytest.mark.parametrize("label,body", LEGACY_SHAPES, ids=[s[0] for s in LEGACY_SHAPES])
def test_and_then_losing_the_policy_asks_instead_of_falling_through(home, label, body):
    """The reason the marker matters, executed end to end."""
    text = starter_policy_text(enabled=False) if body is None else body
    (home / "policy.yaml").write_text(text, encoding="utf-8")
    firewall.write_starter_policy(home=home, enabled=True)
    (home / "policy.yaml").unlink()

    decision, reason = _decision(home)
    assert decision == "ask", f"{label}: policy loss produced {decision!r}"
    assert "gone" in reason or "missing" in reason, reason


def test_a_users_own_policy_is_still_never_rewritten(home):
    """Enrolling must not become a licence to touch their file."""
    mine = "blocked_paths:\n  - ~/.ssh\n"
    (home / "policy.yaml").write_text(mine, encoding="utf-8")
    assert firewall.write_starter_policy(home=home, enabled=True) is None
    assert (home / "policy.yaml").read_text() == mine


# ── round 3: three fault shapes that ended as a healthy answer ───────────────

NUL_IN_VALUE = b"blocked_paths:\n  - ~/.ssh/id_rsa\x00\n"
NUL_IN_COMMENT = b"# note\x00 about this policy\nblocked_paths:\n  - ~/.ssh\n"
NUL_ALONE = b"blocked_paths:\n\x00\n"


def _bytes_policy(home, data):
    (home / "policy.yaml").write_bytes(data)
    (home / firewall.INSTALL_MARKER).write_text("enrolled\n")
    return home


# R1. A NUL inside a VALUE is valid UTF-8 and YAML keeps it, so
# `- ~/.ssh/id_rsa\x00` parsed cleanly, never matched the path it names, and the
# call came back CLEAN in 30 ms with no policy_state and no confession. A
# silent no-match is the worst answer a control can give: it is indistinguishable
# from "checked, nothing found". The bytes are checked before YAML sees them,
# because by then the NUL is already inside a value.

@pytest.mark.parametrize("label,data", [
    ("in a value", NUL_IN_VALUE),
    ("on its own line", NUL_ALONE),
    ("in a comment", NUL_IN_COMMENT),
], ids=["value", "line", "comment"])
def test_a_nul_byte_anywhere_is_a_dead_control(home, label, data):
    """Including in a comment: a policy file with a NUL was not hand-written."""
    _bytes_policy(home, data)
    decision, reason = _decision(home)
    assert decision == "ask", f"NUL {label} produced {decision!r}, a silent answer"
    assert "does not parse" in reason, reason


def test_a_nul_in_a_value_no_longer_reports_a_clean_scan(home):
    """The exact round-2 escape: parsed, unmatched, reported healthy."""
    _bytes_policy(home, NUL_IN_VALUE)
    out = firewall.run_hook(CLEAN, home=home).get("hookSpecificOutput", {})
    assert out.get("permissionDecision") == "ask"
    assert "GLS-FW-CLEAN" not in out.get("permissionDecisionReason", "")


def test_control_removing_the_nul_check_brings_the_silent_answer_back(home, monkeypatch):
    """Mutation: without the byte check the NUL rides inside a parsed value."""
    _bytes_policy(home, NUL_IN_VALUE)
    real = firewall.load_policy

    def no_nul_check(path):
        p = pathlib.Path(path)
        raw = p.read_bytes().replace(b"\x00", b"")   # what the parser used to see
        return firewall.parse_policy(raw.decode("utf-8"))

    monkeypatch.setattr(firewall, "load_policy", no_nul_check)
    assert firewall.load_policy(home / "policy.yaml") is not None, (
        "without the byte check the file parses, which is exactly the state "
        "that produced a clean verdict on a corrupt policy"
    )


# R2. A FIFO with no writer blocks in the kernel. The installed hook sat past
# the harness's 10 second timeout with no stdout and no receipt, and a timed-out
# hook FAILS OPEN. The type is now answered from `os.stat` metadata before any
# file object exists, so nothing can block.

@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_a_non_regular_policy_asks_immediately_instead_of_blocking(home, kind, tmp_path):
    """Through a bounded subprocess, because a FIFO read cannot be interrupted.

    This asserted `elapsed < 1.0` around an IN PROCESS call. If the regular file
    check ever goes away the call never returns, so the assertion never runs and
    the suite hangs instead of failing. A deadline the harness can enforce is the
    only version of this test that can go red.
    """
    import os
    (home / firewall.INSTALL_MARKER).write_text("enrolled\n")
    target = home / "policy.yaml"
    if kind == "fifo":
        os.mkfifo(target)
    else:
        target.mkdir()
    try:
        elapsed, out = _hook_subprocess(CLEAN, home)
    finally:
        if kind == "fifo":
            try:
                target.unlink()
            except OSError:
                pass

    assert elapsed < 1.0, (
        f"{kind} took {elapsed:.1f}s; the hook is still blocking on the read and "
        "the harness will time it out and fail open"
    )
    decision = out.get("hookSpecificOutput", {})
    assert decision.get("permissionDecision") == "ask", decision
    assert "cannot be read" in decision.get("permissionDecisionReason", "")


NODE_TYPE_SNIPPET = """
import os, pathlib, sys
from sunglasses import firewall
home = pathlib.Path(os.environ["SUNGLASSES_HOME"])
try:
    firewall.load_policy(home / "policy.yaml")
except firewall.PolicyDown as exc:
    print(exc)
else:
    print("NO EXCEPTION")
"""


def test_the_node_type_is_named_in_the_failure(home):
    """Same reason. `load_policy` on a FIFO is the call that blocks."""
    import os
    (home / firewall.INSTALL_MARKER).write_text("enrolled\n")
    fifo = home / "policy.yaml"
    os.mkfifo(fifo)
    try:
        said = _in_subprocess(NODE_TYPE_SNIPPET, home)
    finally:
        try:
            fifo.unlink()
        except OSError:
            pass
    assert "FIFO" in said, said


# R3. The regression the round-2 PR body claimed and the suite did not contain.

def test_undecodable_bytes_do_not_stop_a_later_pin_decision(home):
    """The named state must not short-circuit the rest of the call.

    The whole reason UnicodeError was classified rather than left to escape is
    that the escaping exception took the later lane down with it. This asserts
    the call still produces a decision and still carries the confession.
    """
    _bytes_policy(home, b"blocked_paths:\n\xff\xfe")

    # Round 4. This drove CLEAN, which needs no pin lane at all, so the name
    # promised a pin decision the body never asked for. The reviewer's mutation
    # returns early on an unreadable policy, and a CLEAN call cannot see the
    # difference. A first sighting can.
    out = firewall.run_hook(NEW_MCP_CALL, home=home).get("hookSpecificOutput", {})
    assert out, "the hook produced no decision at all"
    assert out["permissionDecision"] == "ask"
    rows = [json.loads(line)
            for f in sorted((home / "receipts").glob("*.jsonl"))
            for line in f.read_text().splitlines() if line.strip()]
    assert rows, "no receipt"
    assert rows[-1].get("rule_id") == "GLS-FW-PIN-TOFU", (
        f"the deciding rule was {rows[-1].get('rule_id')!r}; the unreadable "
        f"policy took the pin decision with it"
    )
    assert rows[-1].get("error"), "the receipt does not confess the dead policy"


# ── round 4: through the INSTALLED command, not the imported function ────────
# Every test above calls `run_hook` in this process. That is the right unit for
# the decision logic and the wrong one for two of these faults, because both
# are about what happens at the PROCESS boundary. A FIFO blocks in the kernel
# and the harness kills the hook; an in-process call cannot be killed and cannot
# fail open. The reviewer found exactly this gap twice, so these two drive the
# command a real install runs, `python -m sunglasses.firewall` reading stdin,
# with an isolated `SUNGLASSES_HOME`.

import os as _os
import subprocess as _subprocess
import sys as _sys

_REPO = pathlib.Path(__file__).resolve().parent.parent
HOOK_DEADLINE_S = 2.0


def _hook_subprocess(payload, home, deadline=HOOK_DEADLINE_S):
    """The hook in a SEPARATE PROCESS with a deadline. (elapsed, parsed stdout).

    Named for what it does. It runs this repository's source through
    `python -m sunglasses.firewall`, not an installed wheel, so it does not
    prove packaging. What it does prove is the only thing these two faults are
    about: that the process can be KILLED. A FIFO blocks in the kernel, and in
    the test process there is nothing to kill it, so an in-process version of
    that assertion passes while a real install sits past its deadline and the
    host fails open. `test_v056_matrix.py` owns the console-script and wheel
    legs; this file owns the boundary.
    """
    import time as _time
    env = dict(_os.environ, SUNGLASSES_HOME=str(home), PYTHONPATH=str(_REPO))
    started = _time.perf_counter()
    proc = _subprocess.run(
        [_sys.executable, "-m", "sunglasses.firewall"],
        input=payload, capture_output=True, text=True,
        cwd=str(_REPO), env=env, timeout=deadline,
    )
    elapsed = _time.perf_counter() - started
    assert proc.returncode == 0, (
        f"the hook exited {proc.returncode}; a non-zero exit is a fail-open. "
        f"stderr {proc.stderr[:300]!r}"
    )
    return elapsed, (json.loads(proc.stdout) if proc.stdout.strip() else {})


def _in_subprocess(snippet, home, deadline=HOOK_DEADLINE_S):
    """Run a snippet against this source with a deadline. Returns its stdout.

    For the assertions that call into `firewall` directly rather than through
    the hook. Same reason as above: with the regular-file check removed, an
    in-process `load_policy` on a FIFO never returns and takes the whole suite
    with it, which is a hang rather than a failure.
    """
    env = dict(_os.environ, SUNGLASSES_HOME=str(home), PYTHONPATH=str(_REPO))
    proc = _subprocess.run([_sys.executable, "-c", snippet], capture_output=True,
                           text=True, cwd=str(_REPO), env=env, timeout=deadline)
    assert proc.returncode == 0, f"snippet exited {proc.returncode}: {proc.stderr[:400]}"
    return proc.stdout.strip()


def _receipt_rows(home):
    return [json.loads(line)
            for f in sorted((home / "receipts").glob("*.jsonl"))
            for line in f.read_text().splitlines() if line.strip()]


def test_an_unreadable_policy_and_a_first_sighting_both_reach_the_same_receipt(home):
    """The regression the round 2 PR body claimed and the suite did not contain.

    An invalid-byte policy AND a tool this install has never seen, on one call,
    in a separate process. The pin lane must still decide, and the
    receipt it writes must confess that the policy control was down while it
    did. The reviewer's surviving mutation returns early on
    `state == "unreadable"`, which produces a policy answer where the TOFU
    answer belongs, and every one of the 362 firewall tests stayed green.
    """
    (home / firewall.INSTALL_MARKER).write_text("enrolled\n")
    (home / "policy.yaml").write_bytes(b"blocked_paths:\n\xff\xfe\n")

    _elapsed, out = _hook_subprocess(NEW_MCP_CALL, home)
    decision = out.get("hookSpecificOutput", {})
    assert decision.get("permissionDecision") == "ask", decision

    rows = _receipt_rows(home)
    assert rows, "the installed hook wrote no receipt at all"
    last = rows[-1]
    assert last.get("rule_id") == "GLS-FW-PIN-TOFU", (
        f"the deciding rule was {last.get('rule_id')!r}. The policy lane answered "
        f"where the pin lane should have, which is the reviewer's mutation."
    )
    assert last.get("degraded") is True, last
    assert last.get("policy_state") == "unreadable", last
    assert last.get("error"), "the receipt does not say the policy control was down"


def test_a_fifo_policy_answers_in_a_separate_process_within_a_second(home):
    """R2, at the boundary where it actually bit.

    A FIFO with no writer blocks in the kernel. In this process there is no
    harness to time the hook out, so the in-process version of this test could
    pass while a real install sat past its deadline and the host failed open.
    The subprocess has a hard deadline, so a regression here is a
    TimeoutExpired rather than a green run.
    """
    (home / firewall.INSTALL_MARKER).write_text("enrolled\n")
    fifo = home / "policy.yaml"
    _os.mkfifo(fifo)
    try:
        elapsed, out = _hook_subprocess(CLEAN, home)
    finally:
        try:
            fifo.unlink()
        except OSError:
            pass

    assert elapsed < 1.0, f"the installed hook took {elapsed:.2f}s on a FIFO"
    decision = out.get("hookSpecificOutput", {})
    assert decision.get("permissionDecision") == "ask", decision
    assert "cannot be read" in decision.get("permissionDecisionReason", "")


# ═══ COST — the guard has to ANSWER, and a big document is not an excuse ═════
#
# ASTRA's round-4 blocker on #173, and the shape is the one this file exists
# for: a hook that misses the harness deadline FAILS OPEN, in silence, with no
# terminal receipt. The ownership rule added in round 4 asked "does anything
# else contain me?" by walking the whole match list for every occurrence, so a
# document carrying 16,000 credential-shaped tokens never reached a decision
# and the call went through unexamined. A correctness fix that stops answering
# on large input has not made the firewall safer, it has moved the hole.
#
# These run through `python -m sunglasses.firewall` with the SHIPPED timeout
# rather than a number chosen here, because the deadline that matters is the
# one the installed hook actually gets.

_COST_TOKENS = 16000


def _cost_document(count=_COST_TOKENS, unique=False):
    """`count` credential-shaped tokens, ASTRA's shape: an Anthropic prefix and
    a 40-character q/Q body, which is material rather than filler and is also
    the overlap case -- two rules match every one of them."""
    import random as _random
    draw = _random.Random(173)
    out = []
    body = "".join(draw.choice("qQ") for _ in range(40))
    for index in range(count):
        out.append("sk" + "-ant-" + ("".join(draw.choice("qQ") for _ in range(40))
                                     if unique else body))
    return " " + " ".join(out)


def _cost_payload(document):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "WebFetch",
                       "tool_input": {"url": "https://example.com/review",
                                      "prompt": document}})


def _denied(out):
    decision = out.get("hookSpecificOutput", {})
    return decision.get("permissionDecision") == "deny"


@pytest.mark.parametrize("unique", [False, True], ids=["COST-16000", "COST-16000-UNIQUE"])
def test_a_document_of_16000_credentials_is_answered_inside_the_shipped_deadline(home, unique):
    """Both of ASTRA's blocking controls.

    The assertion is the DEADLINE, not a stopwatch reading: `_hook_subprocess`
    raises TimeoutExpired if the process has to be killed, which is exactly the
    fail-open being tested. The seconds this takes on any given machine are
    recorded by the curve below as evidence and asserted nowhere.

    Repeated and unique are different defects wearing one number. Repeated is
    fixed by judging each distinct token once; unique cannot be, and needs the
    ownership pass itself to stop being quadratic.
    """
    (home / firewall.INSTALL_MARKER).write_text("enrolled\n")
    _elapsed, out = _hook_subprocess(_cost_payload(_cost_document(unique=unique)),
                                     home, deadline=firewall._HOOK_TIMEOUT)
    assert _denied(out), (
        f"16,000 live credentials were not denied: {out}. A document big enough "
        f"to be slow is a document big enough to matter.")


def test_the_cost_curve_is_recorded_as_evidence(home):
    """1,000 to 16,000, written down rather than asserted.

    Times are observations on whatever machine ran them -- they are not a
    threshold and a slower laptop is not a regression. The curve is here so the
    SHAPE is visible: the quadratic version measured 0.066 / 0.251 / 1.003 /
    3.653 s at 1k / 2k / 4k / 8k and never finished 16k, and a doubling that
    quadruples the time is the thing to notice, whatever the absolute numbers.
    """
    (home / firewall.INSTALL_MARKER).write_text("enrolled\n")
    curve = {}
    for count in (1000, 2000, 4000, 8000, 16000):
        elapsed, out = _hook_subprocess(_cost_payload(_cost_document(count=count)),
                                        home, deadline=firewall._HOOK_TIMEOUT)
        assert _denied(out), f"{count} credentials were not denied: {out}"
        curve[count] = round(elapsed, 3)
    evidence = _REPO / "tests" / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "firewall_cost_curve.json").write_text(json.dumps(curve, indent=2))
    print("cost curve (seconds, this host):", curve)
