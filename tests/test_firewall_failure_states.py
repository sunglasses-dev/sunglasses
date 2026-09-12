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
    import os
    import time
    (home / firewall.INSTALL_MARKER).write_text("enrolled\n")
    target = home / "policy.yaml"
    if kind == "fifo":
        os.mkfifo(target)
    else:
        target.mkdir()

    started = time.perf_counter()
    decision, reason = _decision(home)
    elapsed = time.perf_counter() - started

    assert elapsed < 1.0, (
        f"{kind} took {elapsed:.1f}s; the hook is still blocking on the read and "
        "the harness will time it out and fail open"
    )
    assert decision == "ask", f"{kind} produced {decision!r}"
    assert "cannot be read" in reason, reason


def test_the_node_type_is_named_in_the_failure(home):
    import os
    (home / firewall.INSTALL_MARKER).write_text("enrolled\n")
    os.mkfifo(home / "policy.yaml")
    with pytest.raises(PolicyDown) as caught:
        firewall.load_policy(home / "policy.yaml")
    assert "FIFO" in str(caught.value), str(caught.value)


# R3. The regression the round-2 PR body claimed and the suite did not contain.

def test_undecodable_bytes_do_not_stop_a_later_pin_decision(home):
    """The named state must not short-circuit the rest of the call.

    The whole reason UnicodeError was classified rather than left to escape is
    that the escaping exception took the later lane down with it. This asserts
    the call still produces a decision and still carries the confession.
    """
    _bytes_policy(home, b"blocked_paths:\n\xff\xfe")
    out = firewall.run_hook(CLEAN, home=home).get("hookSpecificOutput", {})
    assert out, "the hook produced no decision at all"
    assert out["permissionDecision"] == "ask"
    assert "cannot be read" in out["permissionDecisionReason"]
